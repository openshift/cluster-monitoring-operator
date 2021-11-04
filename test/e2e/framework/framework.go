// Copyright 2018 The Cluster Monitoring Operator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package framework

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"

	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	schedulingv1client "k8s.io/client-go/kubernetes/typed/scheduling/v1"
	"k8s.io/client-go/tools/clientcmd"

	openshiftconfigclientset "github.com/openshift/client-go/config/clientset/versioned"
	routev1 "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	"github.com/openshift/cluster-monitoring-operator/pkg/client"

	"github.com/pkg/errors"
	monClient "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned/typed/monitoring/v1"
	admissionclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	apiservicesclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"
)

const (
	namespaceName             = "openshift-monitoring"
	userWorkloadNamespaceName = "openshift-user-workload-monitoring"
	e2eServiceAccount         = "cluster-monitoring-operator-e2e"
)

type Framework struct {
	RestConfig            *rest.Config
	OperatorClient        *client.Client
	OpenShiftConfigClient openshiftconfigclientset.Interface
	OpenShiftRouteClient  *routev1.RouteV1Client
	KubeClient            kubernetes.Interface
	ThanosQuerierClient   *PrometheusClient
	PrometheusK8sClient   *PrometheusClient
	AlertmanagerClient    *PrometheusClient
	APIServicesClient     *apiservicesclient.Clientset
	AdmissionClient       *admissionclient.AdmissionregistrationV1Client
	MetricsClient         *metricsclient.Clientset
	SchedulingClient      *schedulingv1client.SchedulingV1Client
	kubeConfigPath        string

	MonitoringClient             *monClient.MonitoringV1Client
	Ns, UserWorkloadMonitoringNs string
}

// New returns a new cluster monitoring operator end-to-end test framework and
// triggers all the setup logic.
func New(kubeConfigPath string) (*Framework, cleanUpFunc, error) {
	ctx := context.Background()
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return nil, nil, err
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating kubeClient failed")
	}

	// Necessary to test the operator status.
	openshiftConfigClient, err := openshiftconfigclientset.NewForConfig(config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating openshiftConfigClient failed")
	}

	// So far only necessary for prometheusK8sClient.
	openshiftRouteClient, err := routev1.NewForConfig(config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating openshiftRouteClient failed")
	}

	mClient, err := monClient.NewForConfig(config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating monitoring client failed")
	}

	operatorClient, err := client.NewForConfig(config, "", namespaceName, userWorkloadNamespaceName)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating operator client failed")
	}

	apiServicesClient, err := apiservicesclient.NewForConfig(config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating API services client failed")
	}

	admissionClient, err := admissionclient.NewForConfig(config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating admission registration client failed")
	}

	metricsClient, err := metricsclient.NewForConfig(config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating metrics client failed")
	}

	schedulingClient, err := schedulingv1client.NewForConfig(config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating scheduling v1 client failed")
	}

	f := &Framework{
		RestConfig:               config,
		OperatorClient:           operatorClient,
		OpenShiftConfigClient:    openshiftConfigClient,
		OpenShiftRouteClient:     openshiftRouteClient,
		KubeClient:               kubeClient,
		APIServicesClient:        apiServicesClient,
		AdmissionClient:          admissionClient,
		MetricsClient:            metricsClient,
		MonitoringClient:         mClient,
		Ns:                       namespaceName,
		UserWorkloadMonitoringNs: userWorkloadNamespaceName,
		kubeConfigPath:           kubeConfigPath,
		SchedulingClient:         schedulingClient,
	}

	cleanUp, err := f.setup()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to setup test framework")
	}

	token, err := f.GetServiceAccountToken(namespaceName, e2eServiceAccount)
	if err != nil {
		return nil, nil, err
	}

	// Prometheus client depends on setup above.
	f.ThanosQuerierClient, err = NewPrometheusClientFromRoute(
		ctx,
		openshiftRouteClient,
		namespaceName, "thanos-querier",
		token,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating ThanosQuerierClient failed")
	}

	f.PrometheusK8sClient, err = NewPrometheusClientFromRoute(
		ctx,
		openshiftRouteClient,
		namespaceName, "prometheus-k8s",
		token,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating PrometheusK8sClient failed")
	}

	f.AlertmanagerClient, err = NewPrometheusClientFromRoute(
		ctx,
		openshiftRouteClient,
		namespaceName, "alertmanager-main",
		token,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating AlertmanagerClient failed")
	}

	return f, cleanUp, nil
}

type cleanUpFunc func() error

// setup creates everything necessary to use the test framework.
func (f *Framework) setup() (cleanUpFunc, error) {
	cleanUpFuncs := []cleanUpFunc{}

	cf, err := f.CreateServiceAccount(f.Ns, e2eServiceAccount)
	if err != nil {
		return nil, err
	}

	cleanUpFuncs = append(cleanUpFuncs, cf)

	cf, err = f.CreateClusterRoleBinding(f.Ns, e2eServiceAccount, "cluster-monitoring-view")
	if err != nil {
		return nil, err
	}

	cleanUpFuncs = append(cleanUpFuncs, cf)

	cf, err = f.CreateRoleBindingFromRole(f.Ns, e2eServiceAccount, "monitoring-alertmanager-edit")
	if err != nil {
		return nil, err
	}

	cleanUpFuncs = append(cleanUpFuncs, cf)

	return func() error {
		var errs []error
		for _, f := range cleanUpFuncs {
			err := f()
			if err != nil {
				errs = append(errs, err)
			}
		}

		if len(errs) != 0 {
			var combined []string
			for _, err := range errs {
				combined = append(combined, err.Error())
			}
			return errors.Errorf("failed to run clean up functions of clean up function: %v", strings.Join(combined, ","))
		}

		return nil
	}, nil
}

func (f *Framework) CreateServiceAccount(namespace, serviceAccount string) (cleanUpFunc, error) {
	ctx := context.Background()
	sa := &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccount,
			Namespace: namespace,
			Labels: map[string]string{
				E2eTestLabelName: E2eTestLabelValue,
			},
		},
	}

	sa, err := f.KubeClient.CoreV1().ServiceAccounts(namespace).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return func() error {
		return f.KubeClient.CoreV1().ServiceAccounts(namespace).Delete(ctx, sa.Name, metav1.DeleteOptions{})
	}, nil
}

func (f *Framework) GetServiceAccountToken(namespace, name string) (string, error) {
	ctx := context.Background()
	var token string
	err := Poll(5*time.Second, time.Minute, func() error {
		secrets, err := f.KubeClient.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}
		for _, secret := range secrets.Items {
			// we have to skip the token secret that contains the openshift.io/create-dockercfg-secrets annotation
			// as this is the token to talk to the internal registry.
			if _, dockerToken := secret.Annotations["openshift.io/create-dockercfg-secrets"]; dockerToken {
				continue
			}
			if strings.Contains(secret.Name, fmt.Sprintf("%s-token-", name)) {
				token = string(secret.Data["token"])
				return nil
			}
		}
		return errors.Errorf("cannot find token for %s/%s service account", namespace, name)
	})
	return token, err
}

func (f *Framework) GetLogs(namespace string, podName, containerName string) (string, error) {
	ctx := context.Background()
	logs, err := f.KubeClient.CoreV1().RESTClient().Get().
		Resource("pods").
		Namespace(namespace).
		Name(podName).SubResource("log").
		Param("container", containerName).
		Do(ctx).
		Raw()
	if err != nil {
		return "", err
	}
	return string(logs), err
}

func (f *Framework) CreateClusterRoleBinding(namespace, serviceAccount, clusterRole string) (cleanUpFunc, error) {
	ctx := context.Background()
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s", serviceAccount, clusterRole),
			Labels: map[string]string{
				E2eTestLabelName: E2eTestLabelValue,
			},
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccount,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     clusterRole,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	clusterRoleBinding, err := f.KubeClient.RbacV1().ClusterRoleBindings().Create(ctx, clusterRoleBinding, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return func() error {
		return f.KubeClient.RbacV1().ClusterRoleBindings().Delete(ctx, clusterRoleBinding.Name, metav1.DeleteOptions{})
	}, nil
}

func (f *Framework) CreateRoleBindingFromClusterRole(namespace, serviceAccount, clusterRole string) (cleanUpFunc, error) {
	ctx := context.Background()
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s", serviceAccount, clusterRole),
			Labels: map[string]string{
				E2eTestLabelName: E2eTestLabelValue,
			},
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccount,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     clusterRole,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	roleBinding, err := f.KubeClient.RbacV1().RoleBindings(namespace).Create(ctx, roleBinding, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return func() error {
		return f.KubeClient.RbacV1().RoleBindings(namespace).Delete(ctx, roleBinding.Name, metav1.DeleteOptions{})
	}, nil
}

func (f *Framework) CreateRoleBindingFromRole(namespace, serviceAccount, role string) (cleanUpFunc, error) {
	ctx := context.Background()
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s", serviceAccount, role),
			Labels: map[string]string{
				E2eTestLabelName: E2eTestLabelValue,
			},
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccount,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     role,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	roleBinding, err := f.KubeClient.RbacV1().RoleBindings(namespace).Create(ctx, roleBinding, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return func() error {
		return f.KubeClient.RbacV1().RoleBindings(namespace).Delete(ctx, roleBinding.Name, metav1.DeleteOptions{})
	}, nil
}

func (f *Framework) ForwardPort(t *testing.T, svc string, port int) (string, func(), error) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	// Taken from github.com/openshift/origin/test/extended/etcd/etcd_test_runner.go
	cmd := exec.CommandContext(ctx, "oc", "port-forward", fmt.Sprintf("service/%s", svc), fmt.Sprintf(":%d", port), "-n", f.Ns, "--kubeconfig", f.kubeConfigPath)

	cleanUp := func() {
		cancel()
		_ = cmd.Wait() // wait to clean up resources but ignore returned error since cancel kills the process
	}

	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		cleanUp()
		return "", nil, errors.Wrap(err, "fail to open stdout")
	}

	stdErr, err := cmd.StderrPipe()
	if err != nil {
		cleanUp()
		return "", nil, errors.Wrap(err, "fail to open stderr")
	}
	go func() {
		scanner := bufio.NewScanner(stdErr)
		for scanner.Scan() {
			t.Log(scanner.Text())
		}
		if err != nil {
			t.Logf("stderr: %v", scanner.Err())
		}
	}()

	err = cmd.Start()
	if err != nil {
		cleanUp()
		return "", nil, errors.Wrap(err, "fail to run command")
	}

	scanner := bufio.NewScanner(stdOut)
	if !scanner.Scan() {
		err := scanner.Err()
		if err == nil {
			err = errors.New("got EOF")
		}
		cleanUp()
		return "", nil, errors.Wrap(err, "fail to read stdout")
	}
	output := scanner.Text()

	re := regexp.MustCompile(`^Forwarding from [^:]+:(\d+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) != 2 {
		cleanUp()
		return "", nil, errors.Wrapf(err, "fail to parse port's value: %q", output)
	}
	_, err = strconv.Atoi(matches[1])
	if err != nil {
		cleanUp()
		return "", nil, errors.Wrapf(err, "fail to convert port's value: %q", output)
	}

	return fmt.Sprintf("127.0.0.1:%s", matches[1]), cleanUp, nil
}

// Poll calls the given function f every given interval
// until it returns no error or the given timeout occurs.
// If a timeout occurs, the last observed error is returned
// or wait.ErrWaitTimeout if no error occurred.
func Poll(interval, timeout time.Duration, f func() error) error {
	var lastErr error

	err := wait.Poll(interval, timeout, func() (bool, error) {
		lastErr = f()
		if lastErr != nil {
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = fmt.Errorf("%v: %v", err, lastErr)
		}
	}

	return err
}

// StartPortForward initiates a port forwarding connection to a pod on the localhost interface.
//
// StartPortForward blocks until the port forwarding proxy server is ready to receive connections.
func (f *Framework) StartPortForward(scheme string, name string, ns string, port string) error {
	roundTripper, upgrader, err := spdy.RoundTripperFor(f.RestConfig)
	if err != nil {
		return err
	}

	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", ns, name)
	hostIP := strings.TrimLeft(f.RestConfig.Host, "htps:/")
	serverURL := url.URL{Scheme: scheme, Path: path, Host: hostIP}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: roundTripper}, http.MethodPost, &serverURL)

	stopChan, readyChan := make(chan struct{}, 1), make(chan struct{}, 1)
	out, errOut := new(bytes.Buffer), new(bytes.Buffer)
	forwarder, err := portforward.New(dialer, []string{port}, stopChan, readyChan, out, errOut)
	if err != nil {
		return err
	}

	go func() {
		if err := forwarder.ForwardPorts(); err != nil {
			panic(err)
		}
	}()

	<-readyChan
	return nil
}
