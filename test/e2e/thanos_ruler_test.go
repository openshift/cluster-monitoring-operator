package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestUserWorkloadThanosRulerWithAdditionalAlertmanagers(t *testing.T) {
	setupUserWorkloadAssetsWithTeardownHook(t, f)

	// Additional alertmanager
	alertmanagerName := "alertmanager-e2e-test"
	alertmanagerService := "alertmanager-operated"
	uwmCM := f.BuildUserWorkloadConfigMap(t,
		fmt.Sprintf(`thanosRuler:
  additionalAlertmanagerConfigs:
  - scheme: http
    apiVersion: v2
    staticConfigs: ["dnssrv+_web._tcp.%s.%s.svc"]
`, alertmanagerService, f.UserWorkloadMonitoringNs),
	)
	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	createAlertmanager(t, f.UserWorkloadMonitoringNs, alertmanagerName)
	t.Cleanup(func() {
		deleteAlertmanager(t, f.UserWorkloadMonitoringNs, alertmanagerName)
	})

	for _, check := range []struct {
		name string
		f    func(*testing.T)
	}{
		{
			name: "assert thanos ruler rollout",
			f:    assertThanosRulerDeployment,
		},
		{
			name: "create UWM alerting rule that always fires and verify additional alertmanager received alerts",
			f: func(t *testing.T) {
				createPrometheusRule(t, "default", "always-firing-alert", "AlwaysFiring")
				verifyAlertmanagerReceivedAlerts(t, f.UserWorkloadMonitoringNs, alertmanagerService)
			},
		},
	} {
		t.Run(check.name, func(t *testing.T) {
			t.Parallel()
			check.f(t)
		})
	}
}

func createAlertmanager(t *testing.T, namespace, name string) {
	ctx := context.Background()
	replicas := int32(1)
	additionalAlertmanager := monitoringv1.Alertmanager{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
			Annotations: map[string]string{
				"operator.prometheus.io/controller-id": "openshift-user-workload-monitoring/prometheus-operator",
			},
		},
		Spec: monitoringv1.AlertmanagerSpec{
			Replicas: &replicas,
		},
	}
	if err := f.OperatorClient.CreateOrUpdateAlertmanager(ctx, &additionalAlertmanager); err != nil {
		t.Fatal(err)
	}

	if err := f.OperatorClient.WaitForAlertmanager(ctx, &additionalAlertmanager); err != nil {
		t.Fatal(err)
	}
}

func deleteAlertmanager(t *testing.T, namespace, name string) {
	amClient := f.MonitoringClient.Alertmanagers(namespace)
	if err := amClient.Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
}

func createPrometheusRule(t *testing.T, namespace, name, alertName string) {
	ctx := context.Background()
	if err := f.OperatorClient.CreateOrUpdatePrometheusRule(ctx, &monitoringv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Spec: monitoringv1.PrometheusRuleSpec{
			Groups: []monitoringv1.RuleGroup{
				{
					Name: "test-group",
					Rules: []monitoringv1.Rule{
						{
							Alert: alertName,
							Expr:  intstr.FromString("vector(1)"),
						},
					},
				},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func verifyAlertmanagerReceivedAlerts(t *testing.T, namespace, svc string) {
	err := framework.Poll(time.Second, 5*time.Minute, func() error {
		host, cleanUp, err := f.ForwardPort(t, namespace, svc, 9093)
		if err != nil {
			return err
		}
		defer cleanUp()

		resp, err := http.Get(fmt.Sprintf("http://%s/api/v2/alerts", host))
		if err != nil {
			return err
		}

		payload, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if string(payload) == "[]\n" {
			return fmt.Errorf("alertmanager received no alerts")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
