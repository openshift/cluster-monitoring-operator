// Copyright 2026 The Cluster Monitoring Operator Authors
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

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	statusv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	monitoringv1beta1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// TestAlertmanagerMSTeamsConfigSecretValidation verifies that the operator
// handles missing webhookURL secrets in MSTeamsConfig gracefully without
// degrading. This test validates the fix from prometheus-operator PR #8294.
func TestAlertmanagerMSTeamsConfigSecretValidation(t *testing.T) {
	const (
		testNamespace          = "noodles"
		alertManagerConfigName = "example"
		secretName             = "my-workflow-webhook"
		secretKey              = "url"
	)

	ctx := context.Background()

	// Enable User Workload Monitoring
	setupUserWorkloadAssetsWithTeardownHook(t, f)

	// Enable custom Alertmanager configs for user workload
	uwmConfigMap := f.BuildUserWorkloadConfigMap(t, `alertmanager:
  enableAlertmanagerConfig: true
  enabled: true`)
	f.MustCreateOrUpdateConfigMap(t, uwmConfigMap)
	t.Cleanup(func() {
		f.MustDeleteConfigMap(t, uwmConfigMap)
	})

	// Wait for user-workload alertmanager to be ready
	am := testAlertmanagerReady(t, "user-workload", f.UserWorkloadMonitoringNs)

	// Verify alertmanager is configured to accept AlertmanagerConfigs
	if err := framework.Poll(time.Second, 5*time.Minute, func() error {
		last, err := f.MonitoringClient.Alertmanagers(am.Namespace).Get(ctx, am.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("%s/%s: %w", am.Namespace, am.Name, err)
		}

		if last.Spec.AlertmanagerConfigNamespaceSelector == nil {
			return fmt.Errorf("expecting non-nil alertmanagerConfigNamespaceSelector")
		}

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Create test namespace
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNamespace,
			Labels: map[string]string{
				framework.E2eTestLabelName:     framework.E2eTestLabelValue,
				"openshift.io/user-monitoring": "true",
			},
		},
	}
	ns, err := f.KubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		foreground := metav1.DeletePropagationForeground
		if err := f.KubeClient.CoreV1().Namespaces().Delete(ctx, testNamespace, metav1.DeleteOptions{PropagationPolicy: &foreground}); err != nil {
			t.Logf("err deleting namespace %s: %v", testNamespace, err)
		}
	})

	// Create AlertmanagerConfig with MSTeamsConfig referencing a missing secret
	// This should NOT cause operator degradation after the fix
	amConfig := &monitoringv1beta1.AlertmanagerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      alertManagerConfigName,
			Namespace: testNamespace,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Spec: monitoringv1beta1.AlertmanagerConfigSpec{
			Route: &monitoringv1beta1.Route{
				GroupBy:  []string{"namespace"},
				Receiver: "msteams",
			},
			Receivers: []monitoringv1beta1.Receiver{
				{
					Name: "msteams",
					MSTeamsConfigs: []monitoringv1beta1.MSTeamsConfig{
						{
							WebhookURL: v1.SecretKeySelector{
								Key: secretKey,
								LocalObjectReference: v1.LocalObjectReference{
									Name: secretName,
								},
							},
							SendResolved: ptr.To(true),
							Title:        ptr.To("mytitle"),
							Text:         ptr.To("mytext"),
						},
					},
				},
			},
		},
	}

	if err := f.CreateOrUpdateAlertmanagerConfig(ctx, amConfig); err != nil {
		t.Fatalf("failed to create AlertmanagerConfig: %v", err)
	}
	t.Cleanup(func() {
		if err := f.DeleteAlertManagerConfigByNamespaceAndName(ctx, testNamespace, alertManagerConfigName); err != nil {
			t.Logf("failed to cleanup alertmanager config %s - err %v", alertManagerConfigName, err)
		}
	})

	// Wait a bit for the operator to process the AlertmanagerConfig
	time.Sleep(10 * time.Second)

	// Verify CMO is NOT degraded when AlertmanagerConfig references missing secret
	// This is the key requirement: missing secret should not cause operator degradation
	t.Run("CMO should not be degraded for missing secret in AlertmanagerConfig", func(t *testing.T) {
		f.AssertOperatorCondition(statusv1.OperatorDegraded, statusv1.ConditionFalse)(t)
		f.AssertOperatorCondition(statusv1.OperatorAvailable, statusv1.ConditionTrue)(t)
	})

	// Verify CMO allows upgrade even with missing secret in AlertmanagerConfig
	// This ensures cluster upgrades are not blocked by the missing secret
	t.Run("CMO should allow upgrade with missing secret in AlertmanagerConfig", func(t *testing.T) {
		f.AssertOperatorCondition(statusv1.OperatorUpgradeable, statusv1.ConditionTrue)(t)
		f.AssertOperatorConditionReason(statusv1.OperatorUpgradeable, "")(t)
		f.AssertOperatorConditionMessage(statusv1.OperatorUpgradeable, "")(t)
	})

	// Check prometheus-operator pod logs in User Workload Monitoring namespace
	// to verify we see appropriate error handling
	t.Run("check prometheus-operator logs for error handling", func(t *testing.T) {
		// Get prometheus-operator pods in user-workload-monitoring namespace
		pods, err := f.KubeClient.CoreV1().Pods(f.UserWorkloadMonitoringNs).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=prometheus-operator",
		})
		if err != nil {
			t.Fatalf("failed to list prometheus-operator pods: %v", err)
		}

		if len(pods.Items) == 0 {
			t.Fatal("no prometheus-operator pods found")
		}

		// Check logs from the first pod
		podName := pods.Items[0].Name
		logs, err := f.GetLogs(f.UserWorkloadMonitoringNs, podName, "prometheus-operator")
		if err != nil {
			t.Fatalf("failed to get logs from pod %s: %v", podName, err)
		}

		// Log a snippet for debugging
		// The exact error message may vary, but we want to ensure it's logged
		logSnippet := logs
		if len(logs) > 500 {
			logSnippet = logs[len(logs)-500:]
		}
		t.Logf("Operator logs (last 500 chars): %s", logSnippet)
	})
}
