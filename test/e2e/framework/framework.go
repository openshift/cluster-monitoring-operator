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
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/imdario/mergo"
	configv1 "github.com/openshift/api/config/v1"
	openshiftconfigclientset "github.com/openshift/client-go/config/clientset/versioned"
	openshiftmonitoringclientset "github.com/openshift/client-go/monitoring/clientset/versioned"
	routev1 "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1beta1"
	monClient "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned/typed/monitoring/v1"
	monBetaClient "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned/typed/monitoring/v1beta1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	admissionclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	schedulingv1client "k8s.io/client-go/kubernetes/typed/scheduling/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	apiservicesclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"
)

const E2eServiceAccount = "cluster-monitoring-operator-e2e"

const (
	namespaceName             = "openshift-monitoring"
	userWorkloadNamespaceName = "openshift-user-workload-monitoring"
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

	OpenShiftMonitoringClient    openshiftmonitoringclientset.Interface
	MonitoringClient             *monClient.MonitoringV1Client
	MonitoringBetaClient         *monBetaClient.MonitoringV1beta1Client
	Ns, UserWorkloadMonitoringNs string

	ManifestsFactory *manifests.Factory
}

// New returns a new cluster monitoring operator end-to-end test framework and
// triggers all the setup logic.
func New(kubeConfigPath string) (*Framework, CleanUpFunc, error) {
	ctx := context.Background()
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return nil, nil, err
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("creating kubeClient failed: %w", err)
	}

	// Necessary to test the operator status.
	openshiftConfigClient, err := openshiftconfigclientset.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("creating openshiftConfigClient failed: %w", err)
	}

	// So far only necessary for prometheusK8sClient.
	openshiftRouteClient, err := routev1.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("creating openshiftRouteClient failed: %w", err)
	}

	mClient, err := monClient.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("creating monitoring client failed: %w", err)
	}

	mBetaClient, err := monBetaClient.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("creating monitoring beta client failed: %w", err)
	}

	// The event recorder will be used by some CreateOrUpdateXXX utils for creation/update events.
	operatorClient, err := client.NewForConfig(config, "", namespaceName, userWorkloadNamespaceName, client.EventRecorder(events.NewInMemoryRecorder("cluster-monitoring-operator")))
	if err != nil {
		return nil, nil, fmt.Errorf("creating operator client failed: %w", err)
	}

	apiServicesClient, err := apiservicesclient.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("creating API services client failed: %w", err)
	}

	admissionClient, err := admissionclient.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("creating admission registration client failed: %w", err)
	}

	metricsClient, err := metricsclient.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("creating metrics client failed: %w", err)
	}

	schedulingClient, err := schedulingv1client.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("creating scheduling v1 client failed: %w", err)
	}

	osmclient, err := openshiftmonitoringclientset.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("creating openshift monitoring client: %w", err)
	}

	f := &Framework{
		RestConfig:                config,
		OperatorClient:            operatorClient,
		OpenShiftConfigClient:     openshiftConfigClient,
		OpenShiftRouteClient:      openshiftRouteClient,
		KubeClient:                kubeClient,
		APIServicesClient:         apiServicesClient,
		AdmissionClient:           admissionClient,
		MetricsClient:             metricsClient,
		MonitoringClient:          mClient,
		MonitoringBetaClient:      mBetaClient,
		Ns:                        namespaceName,
		UserWorkloadMonitoringNs:  userWorkloadNamespaceName,
		kubeConfigPath:            kubeConfigPath,
		SchedulingClient:          schedulingClient,
		OpenShiftMonitoringClient: osmclient,
		ManifestsFactory: manifests.NewFactory(
			namespaceName,
			userWorkloadNamespaceName,
			nil,
			nil,
			nil,
			manifests.NewAssets("../../assets"),
			&manifests.APIServerConfig{},
			&configv1.Console{},
		),
	}

	cleanUp, err := f.setup()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup test framework: %w", err)
	}

	token, err := f.GetServiceAccountToken(namespaceName, E2eServiceAccount)
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
		return nil, nil, fmt.Errorf("creating ThanosQuerierClient failed: %w", err)
	}

	f.PrometheusK8sClient, err = NewPrometheusClientFromRoute(
		ctx,
		openshiftRouteClient,
		namespaceName, "prometheus-k8s",
		token,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating PrometheusK8sClient failed: %w", err)
	}

	f.AlertmanagerClient, err = NewPrometheusClientFromRoute(
		ctx,
		openshiftRouteClient,
		namespaceName, "alertmanager-main",
		token,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating AlertmanagerClient failed: %w", err)
	}

	return f, cleanUp, nil
}

type CleanUpFunc func() error

// setup creates everything necessary to use the test framework.
func (f *Framework) setup() (CleanUpFunc, error) {
	cleanUpFuncs := []CleanUpFunc{}

	cf, err := f.CreateServiceAccount(f.Ns, E2eServiceAccount)
	if err != nil {
		return nil, err
	}

	cleanUpFuncs = append(cleanUpFuncs, cf)

	cf, err = f.CreateClusterRoleBinding(f.Ns, E2eServiceAccount, "cluster-monitoring-view")
	if err != nil {
		return nil, err
	}

	cleanUpFuncs = append(cleanUpFuncs, cf)

	cf, err = f.CreateRoleBindingFromRole(f.Ns, E2eServiceAccount, "cluster-monitoring-metrics-api")
	if err != nil {
		return nil, err
	}

	cleanUpFuncs = append(cleanUpFuncs, cf)

	cf, err = f.CreateRoleBindingFromRole(f.Ns, E2eServiceAccount, "monitoring-alertmanager-edit")
	if err != nil {
		return nil, err
	}

	cleanUpFuncs = append(cleanUpFuncs, cf)

	cf, err = f.CreateRoleBindingFromClusterRole(f.Ns, E2eServiceAccount, "monitoring-rules-view")
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
			return fmt.Errorf("failed to run clean up functions of clean up function: %v", strings.Join(combined, ","))
		}

		return nil
	}, nil
}

func (f *Framework) CreateServiceAccount(namespace, serviceAccount string) (CleanUpFunc, error) {
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
		return fmt.Errorf("cannot find token for %s/%s service account", namespace, name)
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

func (f *Framework) CreateClusterRoleBinding(namespace, serviceAccount, clusterRole string) (CleanUpFunc, error) {
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

func (f *Framework) CreateRoleBindingFromTypedRole(namespace, serviceAccount string, typedRole *rbacv1.Role) (CleanUpFunc, error) {
	ctx := context.Background()

	role, err := f.KubeClient.RbacV1().Roles(namespace).Create(ctx, typedRole, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("role %s already exists", typedRole.Name)
		}
		return nil, err
	}

	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s", serviceAccount, typedRole.Name),
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
			Name:     role.Name,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	roleBinding, err = f.KubeClient.RbacV1().RoleBindings(namespace).Create(ctx, roleBinding, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("%s %s already exists", roleBinding.GroupVersionKind(), roleBinding.Name)
		}
		return nil, err
	}

	// Wait for the role and role binding to be ready.
	err = Poll(10*time.Second, time.Minute, func() error {
		_, err := f.KubeClient.RbacV1().Roles(namespace).Get(ctx, role.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		_, err = f.KubeClient.RbacV1().RoleBindings(namespace).Get(ctx, roleBinding.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		return nil
	})

	return func() error {
		err := f.KubeClient.RbacV1().Roles(namespace).Delete(ctx, role.Name, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
		err = f.KubeClient.RbacV1().RoleBindings(namespace).Delete(ctx, roleBinding.Name, metav1.DeleteOptions{})
		if err != nil {
			return err
		}

		// Wait for the role and role binding to be deleted.
		err = Poll(10*time.Second, time.Minute, func() error {
			_, err := f.KubeClient.RbacV1().Roles(namespace).Get(ctx, role.Name, metav1.GetOptions{})
			if err == nil {
				return fmt.Errorf("%s %s still exists", role.GroupVersionKind(), role.Name)
			}
			_, err = f.KubeClient.RbacV1().RoleBindings(namespace).Get(ctx, roleBinding.Name, metav1.GetOptions{})
			if err == nil {
				return fmt.Errorf("%s %s still exists", roleBinding.GroupVersionKind(), roleBinding.Name)
			}
			return nil
		})

		return err
	}, nil
}

func (f *Framework) CreateRoleBindingFromClusterRole(namespace, serviceAccount, clusterRole string) (CleanUpFunc, error) {
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

func (f *Framework) CreateRoleBindingFromRole(namespace, serviceAccount, role string) (CleanUpFunc, error) {
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

func (f *Framework) CreateRoleBindingFromRoleOtherNamespace(saNamespace, serviceAccount, role, roleNamespace string) (CleanUpFunc, error) {
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
				Namespace: saNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     role,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	roleBinding, err := f.KubeClient.RbacV1().RoleBindings(roleNamespace).Create(ctx, roleBinding, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return func() error {
		return f.KubeClient.RbacV1().RoleBindings(roleNamespace).Delete(ctx, roleBinding.Name, metav1.DeleteOptions{})
	}, nil
}

func (f *Framework) ForwardPort(t *testing.T, ns, svc string, port int) (string, func(), error) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	// Taken from github.com/openshift/origin/test/extended/etcd/etcd_test_runner.go
	cmd := exec.CommandContext(ctx, "oc", "port-forward", fmt.Sprintf("service/%s", svc), fmt.Sprintf(":%d", port), "-n", ns, "--kubeconfig", f.kubeConfigPath)

	cleanUp := func() {
		cancel()
		_ = cmd.Wait() // wait to clean up resources but ignore returned error since cancel kills the process
	}

	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		cleanUp()
		return "", nil, fmt.Errorf("fail to open stdout: %w", err)
	}

	stdErr, err := cmd.StderrPipe()
	if err != nil {
		cleanUp()
		return "", nil, fmt.Errorf("fail to open stderr: %w", err)
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
		return "", nil, fmt.Errorf("fail to run command: %w", err)
	}

	scanner := bufio.NewScanner(stdOut)
	if !scanner.Scan() {
		err := scanner.Err()
		if err == nil {
			err = errors.New("got EOF")
		}
		cleanUp()
		return "", nil, fmt.Errorf("fail to read stdout: %w", err)
	}
	output := scanner.Text()

	re := regexp.MustCompile(`^Forwarding from [^:]+:(\d+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) != 2 {
		cleanUp()
		return "", nil, fmt.Errorf("fail to parse port's value: %q: %w", output, err)
	}
	_, err = strconv.Atoi(matches[1])
	if err != nil {
		cleanUp()
		return "", nil, fmt.Errorf("fail to convert port's value: %q: %w", output, err)
	}

	return fmt.Sprintf("127.0.0.1:%s", matches[1]), cleanUp, nil
}

// Poll calls the given function f every given interval
// until it returns no error or the given timeout occurs.
// If a timeout occurs, the last observed error is returned
// or wait.ErrWaitTimeout if no error occurred.
func Poll(interval, timeout time.Duration, f func() error) error {
	var lastErr error

	err := wait.PollUntilContextTimeout(context.Background(), interval, timeout, false, func(context.Context) (bool, error) {
		lastErr = f()
		if lastErr != nil {
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		if wait.Interrupted(err) && lastErr != nil {
			err = fmt.Errorf("%w: %w", err, lastErr)
		}
	}

	return err
}

func (f *Framework) CreateOrUpdateAlertmanagerConfig(ctx context.Context, a *v1beta1.AlertmanagerConfig) error {
	client := f.MonitoringBetaClient.AlertmanagerConfigs(a.GetNamespace())
	existing, err := client.Get(ctx, a.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := client.Create(ctx, a, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating AlertmanagerConfig object failed: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("retrieving AlertmanagerConfig object failed: %w", err)
	}

	required := a.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	required.ResourceVersion = existing.ResourceVersion

	_, err = client.Update(ctx, required, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating AlertmanagerConfig object failed: %w", err)
	}
	return nil
}

func (f *Framework) DeleteAlertManagerConfigByNamespaceAndName(ctx context.Context, namespace, name string) error {
	client := f.MonitoringBetaClient.AlertmanagerConfigs(namespace)

	err := client.Delete(ctx, name, metav1.DeleteOptions{})
	// if the object does not exist then everything is good here
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("deleting AlertManagerConfig object failed: %w", err)
	}

	return nil
}

const (
	metadataPrefix = "monitoring.openshift.io/"
)

// mergeMetadata merges labels and annotations from `existing` map into `required` one where `required` has precedence
// over `existing` keys and values. Additionally, function performs filtering of labels and annotations from `exiting` map
// where keys starting from string defined in `metadataPrefix` are deleted. This prevents issues with preserving stale
// metadata defined by the operator
func mergeMetadata(required *metav1.ObjectMeta, existing metav1.ObjectMeta) {
	for k := range existing.Annotations {
		if strings.HasPrefix(k, metadataPrefix) {
			delete(existing.Annotations, k)
		}
	}

	for k := range existing.Labels {
		if strings.HasPrefix(k, metadataPrefix) {
			delete(existing.Labels, k)
		}
	}

	mergo.Merge(&required.Annotations, existing.Annotations)
	mergo.Merge(&required.Labels, existing.Labels)
}

func (f *Framework) CreateNamespace(namespace string) (CleanUpFunc, error) {
	ctx := context.Background()
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
			Labels: map[string]string{
				E2eTestLabelName: E2eTestLabelValue,
			},
		},
	}

	ns, err := f.KubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return func() error {
		return f.KubeClient.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{})
	}, nil
}
