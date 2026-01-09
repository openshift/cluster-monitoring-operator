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
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestUserWorkloadThanosRulerWithAdditionalAlertmanagers(t *testing.T) {
	setupUserWorkloadAssetsWithTeardownHook(t, f)

	// Ensure there is no existing alertmanager in f.UserWorkloadMonitoringNs as we're using
	// the common alertmanager-operated service.
	alertmanagers, err := f.MonitoringClient.Alertmanagers(f.UserWorkloadMonitoringNs).List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, alertmanagers.Items, 0)

	// Deploy the additional alertmanager in f.UserWorkloadMonitoringNs.
	addAlertmanagerName := "test-additional-alertmanager"
	addAlertmanagerService := "alertmanager-operated"
	addAlertmanagerNetworkPolicyName := "test-alertmanager-networkpolicy"
	networkpolicy := networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      addAlertmanagerNetworkPolicyName,
			Namespace: f.UserWorkloadMonitoringNs,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name": "alertmanager",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: func() *corev1.Protocol {
								protocol := corev1.ProtocolTCP
								return &protocol
							}(),
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 9093,
							},
						},
					},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{},
			},
		},
	}

	createNetworkPolicy(t, &networkpolicy)
	createAlertmanager(t, f.UserWorkloadMonitoringNs, addAlertmanagerName)
	t.Cleanup(func() {
		deleteNetworkPolicy(t, &networkpolicy)
		deleteAlertmanager(t, f.UserWorkloadMonitoringNs, addAlertmanagerName)
	})

	// Wire it.
	uwmCM := f.BuildUserWorkloadConfigMap(t,
		fmt.Sprintf(`thanosRuler:
  additionalAlertmanagerConfigs:
  - scheme: http
    apiVersion: v2
    staticConfigs: ["dnssrv+_web._tcp.%s.%s.svc"]
`, addAlertmanagerService, f.UserWorkloadMonitoringNs))
	f.MustCreateOrUpdateConfigMap(t, uwmCM)

	for _, check := range []struct {
		name string
		f    func(*testing.T)
	}{
		{
			name: "assert thanos ruler rollout",
			f:    assertThanosRulerDeployment,
		},
		{
			name: "create UWM alerting rule that always fires and verify the additional alertmanager received the alert",
			f: func(t *testing.T) {
				createPrometheusRuleWithAlert(t, "default", "always-firing-alert", "AlwaysFiring")
				verifyAlertmanagerReceivedAlerts(t, f.UserWorkloadMonitoringNs, addAlertmanagerService)
			},
		},
	} {
		t.Run(check.name, func(t *testing.T) {
			check.f(t)
		})
	}
}

func createAlertmanager(t *testing.T, namespace, name string) {
	ctx := context.Background()
	replicas := int32(1)
	alertmanager := monitoringv1.Alertmanager{
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
	require.NoError(t, f.OperatorClient.CreateOrUpdateAlertmanager(ctx, &alertmanager))
	require.NoError(t, f.OperatorClient.WaitForAlertmanager(ctx, &alertmanager))
}

func deleteAlertmanager(t *testing.T, namespace, name string) {
	amClient := f.MonitoringClient.Alertmanagers(namespace)
	require.NoError(t, amClient.Delete(context.Background(), name, metav1.DeleteOptions{}))
}

func createPrometheusRuleWithAlert(t *testing.T, namespace, name, alertName string) {
	ctx := context.Background()
	err := f.OperatorClient.CreateOrUpdatePrometheusRule(ctx, &monitoringv1.PrometheusRule{
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
	})
	require.NoError(t, err)
}

func verifyAlertmanagerReceivedAlerts(t *testing.T, namespace, svc string) {
	err := framework.Poll(time.Second, 5*time.Minute, func() error {
		host, cleanUp, err := f.ForwardPort(t, namespace, svc, 9093)
		if err != nil {
			return err
		}
		t.Cleanup(cleanUp)
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
	require.NoError(t, err)
}

func createNetworkPolicy(t *testing.T, networkpolicy *networkingv1.NetworkPolicy) {
	ctx := context.Background()
	require.NoError(t, f.OperatorClient.CreateOrUpdateNetworkPolicy(ctx, networkpolicy))
}

func deleteNetworkPolicy(t *testing.T, networkpolicy *networkingv1.NetworkPolicy) {
	require.NoError(t, f.OperatorClient.DeleteNetworkPolicy(ctx, networkpolicy))
}
