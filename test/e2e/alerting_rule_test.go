// Copyright 2023 The Cluster Monitoring Operator Authors
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
	"reflect"

	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	statusv1 "github.com/openshift/api/config/v1"
	osmv1 "github.com/openshift/api/monitoring/v1"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	"github.com/pkg/errors"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	validArName   = "valid-test-alerting-rule"
	invalidArName = "invalid-test-alerting-rule"
)

func TestAlertingRule(t *testing.T) {
	ctx := context.Background()
	alertingRules := f.OpenShiftMonitoringClient.MonitoringV1().AlertingRules(f.Ns)

	ar := &osmv1.AlertingRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      invalidArName,
			Namespace: f.Ns,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Spec: osmv1.AlertingRuleSpec{
			Groups: []osmv1.RuleGroup{
				{
					Name:     "test-group",
					Interval: "15s",
					Rules: []osmv1.Rule{
						{
							Alert:       "InvalidAlert",
							Expr:        intstr.FromString("invalid_expr("),
							For:         "5m",
							Labels:      map[string]string{"severity": "high"},
							Annotations: map[string]string{"summary": "high foo"},
						},
					},
				},
			},
		},
	}

	// The operator is healthy
	f.AssertOperatorCondition(statusv1.OperatorDegraded, statusv1.ConditionFalse)(t)
	f.AssertOperatorCondition(statusv1.OperatorAvailable, statusv1.ConditionTrue)(t)

	initialPrCount := prometheusRuleCount(t)

	// Create an invalid AlertingRule (invalid expression), the corresponding PrometheusRule will not be created
	// due to prometheus-operator admissions webhook, but this should not break the stack: We should still be able
	// to create valid AlertingRules, configure and query Prometheus etc. We'll run some checks as we go along to
	// make sure of that.
	createAlertingRule(t, ar)

	// Create a valid AlertingRule.
	ar.Name = validArName
	ar.Spec.Groups[0].Rules[0].Expr = intstr.FromString("rate(foo{job=\"bar\"}[3m]) > 10")
	ar.Spec.Groups[0].Rules[0].Alert = "ValidAlert-1"
	createAlertingRule(t, ar)

	// Make sure the corresponding PrometheusRule was well generated.
	validatePrometheusRule(t, validArName)
	// And only one PrometheusRule was added (the invalid AlertingRule hasn't generated anything)
	assertPrometheusRuleCount(t, initialPrCount+1)
	// And the invalid AlertingRule didn't prevent Prometheus from taking the valid AlertingRule into account
	f.PrometheusK8sClient.WaitForRulesReturn(t, 5*time.Minute,
		func(body []byte) error {
			return getThanosRules(body, "test-group", "ValidAlert-1")
		},
	)

	// Update the valid AlertingRule.
	ar, err := alertingRules.Get(ctx, validArName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to get the AlertingRule"))
	}
	ar.Spec.Groups[0].Interval = "20s"
	ar.Spec.Groups[0].Rules = append(ar.Spec.Groups[0].Rules, osmv1.Rule{
		Alert:       "ValidAlert-2",
		Expr:        intstr.FromString("rate(bar{job=\"foo\"}[3m]) == 1"),
		For:         "10m",
		Labels:      map[string]string{"severity": "critical"},
		Annotations: map[string]string{"summary": "bar"},
	})
	updateAlertingRule(t, ar)

	// Make sure the corresponding PrometheusRule was well updated.
	validatePrometheusRule(t, validArName)
	// Make sure it still generates one PrometheusRule, this is a sanity check.
	assertPrometheusRuleCount(t, initialPrCount+1)

	// Delete the valid AlertingRule.
	pr, err := generatedPrometheusRule(ar)
	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to get the generated PrometheusRule"))
	}
	deleteAlertingRule(t, validArName)
	// Make sure the corresponding PrometheusRule was deleted.
	f.AssertPrometheusRuleDoesNotExist(pr.Name, pr.Namespace)(t)
	// And still the invalid AlertingRule hasn't generated anything.
	assertPrometheusRuleCount(t, initialPrCount)

	// Even with an invalid AlertingRule, the operator is still healthy
	f.AssertOperatorCondition(statusv1.OperatorDegraded, statusv1.ConditionFalse)(t)
	f.AssertOperatorCondition(statusv1.OperatorAvailable, statusv1.ConditionTrue)(t)
	// Delete the invalid AlertingRule
	deleteAlertingRule(t, invalidArName)
}

func createAlertingRule(t *testing.T, ar *osmv1.AlertingRule) {
	_, err := f.OpenShiftMonitoringClient.MonitoringV1().AlertingRules(f.Ns).Create(ctx, ar, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(errors.Wrap(err, "Failed to create the AlertingRule"))
	}
}

func updateAlertingRule(t *testing.T, ar *osmv1.AlertingRule) {
	_, err := f.OpenShiftMonitoringClient.MonitoringV1().AlertingRules(f.Ns).Update(ctx, ar, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(errors.Wrap(err, "Failed to update the AlertingRule"))
	}
}

func deleteAlertingRule(t *testing.T, arName string) {
	err := f.OpenShiftMonitoringClient.MonitoringV1().AlertingRules(f.Ns).Delete(ctx, arName, metav1.DeleteOptions{})
	if err != nil {
		t.Fatal(errors.Wrap(err, "Failed to delete the AlertingRule"))
	}
}

// prometheusRuleCount returns the count of PrometheusRule
func prometheusRuleCount(t *testing.T) int {
	pr, err := f.MonitoringClient.PrometheusRules(f.Ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(errors.Wrap(err, "Failed to list PrometheusRule"))
	}
	return len(pr.Items)
}

func assertPrometheusRuleCount(t *testing.T, count int) {
	currentCount := prometheusRuleCount(t)
	if currentCount != count {
		t.Fatalf("Different generated PrometheusRule count (%d != %d)", currentCount, count)
	}
}

// generatedPrometheusRule returns the PrometheusRule that was generated by an AlertingRule.
func generatedPrometheusRule(ar *osmv1.AlertingRule) (*monv1.PrometheusRule, error) {
	prName := strings.TrimPrefix(ar.Status.PrometheusRule.Name, fmt.Sprintf("%s/", f.Ns))
	pr, err := f.MonitoringClient.PrometheusRules(f.Ns).Get(ctx, prName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return pr, nil
}

// getResources returns the AlertingRule called arName and its corresponding PrometheusRule if they exist.
func getResources(arName string) (*osmv1.AlertingRule, *monv1.PrometheusRule, error) {
	ar, err := f.OpenShiftMonitoringClient.MonitoringV1().AlertingRules(f.Ns).Get(ctx, arName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	pr, err := generatedPrometheusRule(ar)
	if err != nil {
		return ar, nil, err
	}

	return ar, pr, nil
}

// validatePrometheusRule makes sure the PrometheusRule contains the right data from AlertingRule
func validatePrometheusRule(t *testing.T, arName string) {
	err := framework.Poll(time.Second, 2*time.Minute, func() error {
		ar, pr, err := getResources(arName)
		if err != nil {
			return err
		}

		arGroups := ar.Spec.Groups
		prGroups := pr.Spec.Groups

		if len(arGroups) != len(prGroups) {
			return fmt.Errorf("Different groups count (%d != %d)", len(arGroups), len(prGroups))
		}

		for j, arGroup := range arGroups {
			prGroup := prGroups[j]

			if arGroup.Name != prGroup.Name {
				return fmt.Errorf("Groups have different names (%s != %s)", arGroup.Name, prGroup.Name)
			}

			if string(arGroup.Interval) != string(*prGroup.Interval) {
				return fmt.Errorf("Different group interval (%s != %s)", arGroup.Interval, *prGroup.Interval)
			}

			arRules := arGroup.Rules
			prRules := prGroup.Rules

			if len(arRules) != len(prRules) {
				return fmt.Errorf("Different rules count (%d != %d)", len(arRules), len(prRules))
			}

			for k, rule := range arRules {
				arRule := rule.DeepCopy()
				// CMO sets this labels to all rules
				arRule.Labels["openshift_io_user_alert"] = "true"
				prRule := prRules[k]

				if arRule.Alert != prRule.Alert {
					return fmt.Errorf("Rules have different names (%s != %s)", arRule.Alert, prRule.Alert)
				}

				if string(arRule.For) != string(*prRule.For) {
					return fmt.Errorf("Rules have different for (%s != %s)", arRule.For, *prRule.For)
				}

				if !reflect.DeepEqual(arRule.Annotations, prRule.Annotations) {
					return fmt.Errorf("Rules have different annotations expected %+v, got %+v", arRule.Annotations, prRule.Annotations)
				}

				if !reflect.DeepEqual(arRule.Labels, prRule.Labels) {
					return fmt.Errorf("Rules have different labels expected %+v, got %+v", arRule.Labels, prRule.Labels)
				}
			}
		}
		return nil
	})

	if err != nil {
		t.Fatal(errors.Wrap(err, "Failed to validate the generated PrometheusRule"))
	}
}
