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
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	schedulingv1client "k8s.io/client-go/kubernetes/typed/scheduling/v1"
	"k8s.io/client-go/tools/clientcmd"

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
	OperatorClient      *client.Client
	KubeClient          kubernetes.Interface
	ThanosQuerierClient *PrometheusClient
	PrometheusK8sClient *PrometheusClient
	AlertmanagerClient  *PrometheusClient
	APIServicesClient   *apiservicesclient.Clientset
	AdmissionClient     *admissionclient.AdmissionregistrationV1Client
	MetricsClient       *metricsclient.Clientset
	SchedulingClient    *schedulingv1client.SchedulingV1Client
	kubeConfigPath      string

	MonitoringClient             *monClient.MonitoringV1Client
	Ns, UserWorkloadMonitoringNs string
}

// New returns a new cluster monitoring operator end-to-end test framework and
// triggers all the setup logic.
func New(kubeConfigPath string) (*Framework, cleanUpFunc, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return nil, nil, err
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating kubeClient failed")
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

	operatorClient, err := client.New(config, "", namespaceName, userWorkloadNamespaceName)
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
		OperatorClient:           operatorClient,
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
		openshiftRouteClient,
		namespaceName, "thanos-querier",
		token,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating ThanosQuerierClient failed")
	}

	f.PrometheusK8sClient, err = NewPrometheusClientFromRoute(
		openshiftRouteClient,
		namespaceName, "prometheus-k8s",
		token,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating PrometheusK8sClient failed")
	}

	f.AlertmanagerClient, err = NewPrometheusClientFromRoute(
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
	sa := &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccount,
			Namespace: namespace,
		},
	}

	sa, err := f.KubeClient.CoreV1().ServiceAccounts(namespace).Create(context.TODO(), sa, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return func() error {
		return f.KubeClient.CoreV1().ServiceAccounts(namespace).Delete(context.TODO(), sa.Name, metav1.DeleteOptions{})
	}, nil
}

func (f *Framework) GetServiceAccountToken(namespace, name string) (string, error) {
	var token string
	err := Poll(5*time.Second, time.Minute, func() error {
		secrets, err := f.KubeClient.CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{})
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

func (f *Framework) CreateClusterRoleBinding(namespace, serviceAccount, clusterRole string) (cleanUpFunc, error) {
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s", serviceAccount, clusterRole),
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

	clusterRoleBinding, err := f.KubeClient.RbacV1().ClusterRoleBindings().Create(context.TODO(), clusterRoleBinding, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return func() error {
		return f.KubeClient.RbacV1().ClusterRoleBindings().Delete(context.TODO(), clusterRoleBinding.Name, metav1.DeleteOptions{})
	}, nil
}

func (f *Framework) CreateRoleBindingFromClusterRole(namespace, serviceAccount, clusterRole string) (cleanUpFunc, error) {
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s", serviceAccount, clusterRole),
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

	roleBinding, err := f.KubeClient.RbacV1().RoleBindings(namespace).Create(context.TODO(), roleBinding, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return func() error {
		return f.KubeClient.RbacV1().RoleBindings(namespace).Delete(context.TODO(), roleBinding.Name, metav1.DeleteOptions{})
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
