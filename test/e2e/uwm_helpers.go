package e2e

import (
	"context"
	"fmt"
	"testing"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

const (
	userWorkloadTestNs = "user-workload-test"
	notEnforcedNs      = "namespace-not-enforced"
)

var (
	ctx = context.Background()
)

// getUserWorkloadEnabledConfigMap returns a config map with uwm enabled
func getUserWorkloadEnabledConfigMap(t *testing.T, f *framework.Framework) *v1.ConfigMap {
	t.Helper()

	return f.BuildCMOConfigMap(t, "enableUserWorkload: true")
}

// setupUserWorkloadAssets enables UWM via the config map and asserts resources are up and running
func setupUserWorkloadAssets(t *testing.T, f *framework.Framework) {
	t.Helper()

	f.MustCreateOrUpdateConfigMap(t, getUserWorkloadEnabledConfigMap(t, f))
	f.AssertDeploymentExists("prometheus-operator", f.UserWorkloadMonitoringNs)(t)
	f.AssertStatefulSetExistsAndRollout("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)
	f.AssertPrometheusExists("user-workload", f.UserWorkloadMonitoringNs)(t)
}

// setupUserWorkloadAssetsWithTeardownHook enables UWM via the config map and asserts resources are up and running
// cleans up assets after all subtests run
func setupUserWorkloadAssetsWithTeardownHook(t *testing.T, f *framework.Framework) {
	t.Helper()
	setupUserWorkloadAssets(t, f)

	t.Cleanup(func() {
		tearDownUserWorkloadAssets(t, f)
	})
}

// tearDownUserWorkloadAssets deletes the uwm enabled config map and asserts
// the associated resources are deleted
func tearDownUserWorkloadAssets(t *testing.T, f *framework.Framework) {
	t.Helper()
	if err := f.OperatorClient.DeleteConfigMap(context.Background(), getUserWorkloadEnabledConfigMap(t, f)); err != nil {
		t.Fatal(err)
	}

	f.AssertDeploymentDoesNotExist("prometheus-operator", f.UserWorkloadMonitoringNs)(t)
	f.AssertStatefulsetDoesNotExist("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)
}

func createNamespaceIfNotExist(f *framework.Framework, ns string) error {
	_, err := f.KubeClient.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: ns,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

// deployUserApplication is idempotent and deploys the sample app and resources in UserWorkloadTestNs
func deployUserApplication(f *framework.Framework) error {
	if err := createNamespaceIfNotExist(f, userWorkloadTestNs); err != nil {
		return fmt.Errorf("namespace %s: %w", userWorkloadTestNs, err)
	}

	app, err := f.KubeClient.AppsV1().Deployments(userWorkloadTestNs).Create(ctx, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus-example-app",
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
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
							Name:            "prometheus-example-app",
							Image:           "ghcr.io/rhobs/prometheus-example-app:0.3.0",
							SecurityContext: getSecurityContextRestrictedProfile(),
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
	if err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
	} else {
		err = f.OperatorClient.WaitForDeploymentRollout(ctx, app)
		if err != nil {
			return err
		}
	}

	_, err = f.KubeClient.CoreV1().Services(userWorkloadTestNs).Create(ctx, &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus-example-app",
			Labels: map[string]string{
				"app":                      "prometheus-example-app",
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
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
				"k8s-app":                  "prometheus-example-monitor",
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
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
				"k8s-app":                  "prometheus-example-rule",
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
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
							For:   func(d monitoringv1.Duration) *monitoringv1.Duration { return &d }("1s"),
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
				framework.E2eTestLabelName:                      framework.E2eTestLabelValue,
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

	return nil
}

// deployGlobalRules configures 2 PrometheusRule objects (1 for Thanos Ruler, 1
// for Prometheus) for which the namespace label shouldn't be enforced (at
// least initially).
func deployGlobalRules(f *framework.Framework) error {
	if err := createNamespaceIfNotExist(f, notEnforcedNs); err != nil {
		return fmt.Errorf("namespace %s: %w", notEnforcedNs, err)
	}

	pr := &monitoringv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "global",
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Spec: monitoringv1.PrometheusRuleSpec{
			Groups: []monitoringv1.RuleGroup{
				{
					Name:     "example",
					Interval: ptr.To(monitoringv1.Duration("1s")),
					Rules: []monitoringv1.Rule{
						{
							Record: "test:pods:count",
							Expr:   intstr.FromString(fmt.Sprintf(`count(kube_pod_info{namespace="%s"})`, userWorkloadTestNs)),
							Labels: map[string]string{
								"_source": "thanos-ruler",
							},
						},
					},
				},
			},
		},
	}

	_, err := f.MonitoringClient.PrometheusRules(notEnforcedNs).Create(ctx, pr, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	pr.Name = "global-leaf"
	pr.Labels["openshift.io/prometheus-rule-evaluation-scope"] = "leaf-prometheus"
	// Use the `up` metric for the rule deployed on the user-workload
	// Prometheus since it can't query for `kube_pod_info`.
	pr.Spec.Groups[0].Rules = []monitoringv1.Rule{
		{
			Record: "test:up:count",
			Expr:   intstr.FromString(fmt.Sprintf(`count(up{namespace="%s"})`, userWorkloadTestNs)),
			Labels: map[string]string{
				"_source": "prometheus",
			},
		},
	}
	_, err = f.MonitoringClient.PrometheusRules(notEnforcedNs).Create(ctx, pr, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

func createPrometheusAlertmanagerInUserNamespace(f *framework.Framework) error {
	_, err := f.MonitoringClient.Alertmanagers(userWorkloadTestNs).Create(ctx, &monitoringv1.Alertmanager{
		ObjectMeta: metav1.ObjectMeta{
			Name: "not-to-be-reconciled",
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
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
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Spec: monitoringv1.PrometheusSpec{
			CommonPrometheusFields: monitoringv1.CommonPrometheusFields{
				Replicas: toInt32(1),
			},
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

func toInt32(v int32) *int32 { return &v }
