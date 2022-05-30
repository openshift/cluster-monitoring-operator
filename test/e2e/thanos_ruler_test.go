package e2e

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestUserWorkloadThanosRulerWithAdditionalAlertmanagers(t *testing.T) {
	setupUserWorkloadAssetsWithTeardownHook(t, f)
	uwmCM := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userWorkloadMonitorConfigMapName,
			Namespace: f.UserWorkloadMonitoringNs,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string]string{
			"config.yaml": `thanosRuler:
  additionalAlertmanagerConfigs:
  - scheme: http
    apiVersion: v2
    staticConfigs: ["dnssrv+_web._tcp.alertmanager-operated.openshift-user-workload-monitoring.svc"]
`,
		},
	}
	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	t.Cleanup(func() {
		deleteAlertmanager(t)
	})

	testCases := []struct {
		name      string
		scenarios []scenario
	}{
		{
			name: "Test enabling and disabling additional alertmanager configs",
			scenarios: []scenario{
				{"assert thanos ruler rollout", assertThanosRulerDeployment},
				{"create additional alertmanager", createAlertmanager},
				{"create alerting rule that always fires", createPrometheusRule},
				{"verify alertmanager received the alert", verifyAlertmanagerAlertReceived},
			},
		},
	}

	for _, tt := range testCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			for _, scenario := range tt.scenarios {
				t.Run(scenario.name, scenario.assertion)
			}
		})
	}
}

func createAlertmanager(t *testing.T) {
	ctx := context.Background()
	replicas := int32(1)
	additionalAlertmanager := monitoringv1.Alertmanager{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alertmanager-e2e-test",
			Namespace: f.UserWorkloadMonitoringNs,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
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

func createPrometheusRule(t *testing.T) {
	ctx := context.Background()
	if err := f.OperatorClient.CreateOrUpdatePrometheusRule(ctx, &monitoringv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-monitoring-prometheus-rules",
			Namespace: "default",
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
							Alert: "AdditionalTestAlertRule",
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

func verifyAlertmanagerAlertReceived(t *testing.T) {

	host, cleanUp, err := f.ForwardPort(t, f.Ns, "alertmanager-operated", 9093)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)

	err = framework.Poll(time.Second, 5*time.Minute, func() error {
		resp, err := http.Get(fmt.Sprintf("http://%s/api/v2/alerts", host))
		if err != nil {
			return err
		}

		payload, err := ioutil.ReadAll(resp.Body)
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

func deleteAlertmanager(t *testing.T) {
	amClient := f.MonitoringClient.Alertmanagers(f.UserWorkloadMonitoringNs)
	if err := amClient.Delete(context.Background(), "alertmanager-e2e-test", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
}
