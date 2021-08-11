package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	userWorkloadTestNs = "user-workload-test"
)

var (
	ctx = context.Background()
)

func assertDeletionOfUserWorkloadAssets(f *framework.Framework) func(*testing.T) {
	return func(t *testing.T) {
		tearDownUserWorkloadAssets(t, f)

		f.AssertDeploymentDoesNotExist("prometheus-operator", f.UserWorkloadMonitoringNs)(t)
		f.AssertStatefulsetDoesNotExist("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)
		f.AssertSecretDoesNotExist(manifests.PrometheusUWAdditionalAlertmanagerConfigSecretName, f.UserWorkloadMonitoringNs)(t)
	}
}

// getUserWorkloadEnabledConfigMap returns a config map with uwm enabled
func getUserWorkloadEnabledConfigMap(t *testing.T, f *framework.Framework) *v1.ConfigMap {
	t.Helper()
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      framework.ClusterMonitorConfigMapName,
			Namespace: f.Ns,
		},
		Data: map[string]string{
			"config.yaml": `enableUserWorkload: true
`,
		},
	}
}

// setupUserWorkloadAssets enables UWM via the config map and asserts resources are up and running
func setupUserWorkloadAssets(t *testing.T, f *framework.Framework) {
	t.Helper()

	f.MustCreateOrUpdateConfigMap(t, getUserWorkloadEnabledConfigMap(t, f))
	f.AssertDeploymentExists("prometheus-operator", f.UserWorkloadMonitoringNs)(t)
	f.AssertStatefulSetExistsAndRollout("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)
	f.AssertPrometheusExists("user-workload", f.UserWorkloadMonitoringNs)(t)
}

// tearDownUserWorkloadAssets deletes the uwm enabled config map
func tearDownUserWorkloadAssets(t *testing.T, f *framework.Framework) {
	t.Helper()
	f.OperatorClient.DeleteConfigMap(context.Background(), getUserWorkloadEnabledConfigMap(t, f))
}

// setupUserApplication is idempotent and deploys the sample app and resources in UserWorkloadTestNs
func setupUserApplication(t *testing.T, f *framework.Framework) {
	t.Helper()
	deployUserApplication(t, f)
	createPrometheusAlertmanagerInUserNamespace(t, f)
}

// tearDownUserApplication deletes the UserWorkloadTestNs and waits for deletion
func tearDownUserApplication(t *testing.T, f *framework.Framework) {
	// check if its deleted and return if true
	err := framework.Poll(time.Second, 5*time.Minute, func() error {
		return f.OperatorClient.DeleteIfExists(ctx, userWorkloadTestNs)
	})

	if err != nil {
		t.Fatal(err)
	}

	f.AssertNamespaceDoesNotExist(userWorkloadTestNs)(t)
}

func deployUserApplication(t *testing.T, f *framework.Framework) error {
	t.Helper()
	_, err := f.KubeClient.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: userWorkloadTestNs,
		},
	}, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	f.AssertNamespaceExists(userWorkloadTestNs)(t)

	app, err := f.KubeClient.AppsV1().Deployments(userWorkloadTestNs).Create(ctx, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus-example-app",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: toInt32(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "prometheus-example-app",
				},
			},
			Template: v1.PodTemplateSpec{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "prometheus-example-app",
							Image: "ghcr.io/rhobs/prometheus-example-app:0.3.0",
						},
					},
				},
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "prometheus-example-app",
					},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	_, err = f.KubeClient.CoreV1().Services(userWorkloadTestNs).Create(ctx, &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus-example-app",
			Labels: map[string]string{
				"app": "prometheus-example-app",
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:       "web",
					Protocol:   "TCP",
					Port:       8080,
					TargetPort: intstr.FromInt(8080),
				},
			},
			Selector: map[string]string{
				"app": "prometheus-example-app",
			},
			Type: v1.ServiceTypeClusterIP,
		},
	}, metav1.CreateOptions{})

	_, err = f.MonitoringClient.ServiceMonitors(userWorkloadTestNs).Create(ctx, &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus-example-monitor",
			Labels: map[string]string{
				"k8s-app": "prometheus-example-monitor",
			},
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Endpoints: []monitoringv1.Endpoint{
				{
					Port:     "web",
					Scheme:   "http",
					Interval: "30s",
				},
			},
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "prometheus-example-app",
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	_, err = f.MonitoringClient.PrometheusRules(userWorkloadTestNs).Create(ctx, &monitoringv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus-example-rule",
			Labels: map[string]string{
				"k8s-app": "prometheus-example-rule",
			},
		},
		Spec: monitoringv1.PrometheusRuleSpec{
			Groups: []monitoringv1.RuleGroup{
				{
					Name: "example",
					Rules: []monitoringv1.Rule{
						{
							Record: "version:blah:count",
							Expr:   intstr.FromString(`count(version)`),
						},
						{
							Alert: "VersionAlert",
							Expr:  intstr.FromString(fmt.Sprintf(`version{namespace="%s",job="prometheus-example-app"} == 1`, userWorkloadTestNs)),
							For:   "1s",
						},
					},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	_, err = f.MonitoringClient.PrometheusRules(userWorkloadTestNs).Create(ctx, &monitoringv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus-example-rule-leaf",
			Labels: map[string]string{
				"k8s-app": "prometheus-example-rule-leaf",
				"openshift.io/prometheus-rule-evaluation-scope": "leaf-prometheus",
			},
		},
		Spec: monitoringv1.PrometheusRuleSpec{
			Groups: []monitoringv1.RuleGroup{
				{
					Name: "example",
					Rules: []monitoringv1.Rule{
						{
							Record: "version:blah:leaf:count",
							Expr:   intstr.FromString(`count(version)`),
						},
					},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	err = f.OperatorClient.WaitForDeploymentRollout(ctx, app)
	if err != nil {
		return err
	}
	return nil
}

func createPrometheusAlertmanagerInUserNamespace(t *testing.T, f *framework.Framework) error {
	t.Helper()
	_, err := f.MonitoringClient.Alertmanagers(userWorkloadTestNs).Create(ctx, &monitoringv1.Alertmanager{
		ObjectMeta: metav1.ObjectMeta{
			Name: "not-to-be-reconciled",
		},
		Spec: monitoringv1.AlertmanagerSpec{
			Replicas: toInt32(1),
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	_, err = f.MonitoringClient.Prometheuses(userWorkloadTestNs).Create(ctx, &monitoringv1.Prometheus{
		ObjectMeta: metav1.ObjectMeta{
			Name: "not-to-be-reconciled",
		},
		Spec: monitoringv1.PrometheusSpec{
			Replicas: toInt32(1),
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func toInt32(v int32) *int32 { return &v }
