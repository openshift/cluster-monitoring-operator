// Copyright 2020 The Cluster Monitoring Operator Authors
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

	yaml "github.com/ghodss/yaml"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	monitoringv1beta1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	prometheusRuleWebhookName     = "prometheusrules.openshift.io"
	alertmanagerConfigWebhookName = "alertmanagerconfigs.openshift.io"
)

var (
	validPromRuleYaml = fmt.Sprintf(`---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: valid-rule
  labels:
    %s
spec:
  groups:
  - name: recording-rules
    rules:
    - record: my_always_record_one
      expr: 1
`, framework.E2eTestLabel)

	invalidPromRuleYaml = fmt.Sprintf(`---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: invalid-rule
  labels:
    %s
spec:
  groups:
  - name: invalid-rule-group
    rules:
    - record: invalid_rule
      expr: this+/(fails
`, framework.E2eTestLabel)

	validAmConf = fmt.Sprintf(`---
apiVersion: monitoring.coreos.com/v1beta1
kind: AlertmanagerConfig
metadata:
  name: valid-test-config
  labels:
    %s
spec:
  route:
    groupBy: ['job']
    groupWait: 30s
    groupInterval: 5m
    repeatInterval: 12h
    receiver: 'webhook'
  receivers:
  - name: 'webhook'
    webhookConfigs:
    - url: 'https://example.com'
`, framework.E2eTestLabel)

	invalidAmConf = fmt.Sprintf(`---
apiVersion: monitoring.coreos.com/v1beta1
kind: AlertmanagerConfig
metadata:
  name: invalid-test-config
  labels:
    %s
spec:
  route:
    groupBy: ['job']
    groupWait: 30s
    groupInterval: 5m
    repeatInterval: 12h
    receiver: 'missing-ref'
  receivers:
  - name: 'webhook'
    webhookConfigs:
    - url: 'https://example.com'
`, framework.E2eTestLabel)
)

func TestPrometheusRuleValidatingWebhook(t *testing.T) {
	ctx := context.Background()

	_, err := f.AdmissionClient.ValidatingWebhookConfigurations().Get(ctx, prometheusRuleWebhookName, metav1.GetOptions{})
	if err != nil {
		t.Fatal("unable to get prometheus rules validating webhook", err)
	}

	validPromRule := monitoringv1.PrometheusRule{}
	err = yaml.Unmarshal([]byte(validPromRuleYaml), &validPromRule)
	if err != nil {
		t.Fatal("unable to unmarshal prometheus rule", err)
	}
	_, err = f.MonitoringClient.PrometheusRules(f.Ns).Create(ctx, &validPromRule, metav1.CreateOptions{})
	if err != nil {
		t.Fatal("unable to create prometheus rule", err)
	}

	invalidPromRule := monitoringv1.PrometheusRule{}
	err = yaml.Unmarshal([]byte(invalidPromRuleYaml), &invalidPromRule)
	if err != nil {
		t.Fatal("unable to unmarshal prometheus rule", err)
	}
	_, err = f.MonitoringClient.PrometheusRules(f.Ns).Create(ctx, &invalidPromRule, metav1.CreateOptions{})
	if err == nil {
		t.Fatal("invalid rule was accepted by validatingwebhook")
	}

}

func TestAlertManagerConfigValidatingWebhook(t *testing.T) {
	ctx := context.Background()

	_, err := f.AdmissionClient.ValidatingWebhookConfigurations().Get(ctx, alertmanagerConfigWebhookName, metav1.GetOptions{})
	if err != nil {
		t.Fatal("unable to get alertmanagerconfig validating webhook", err)
	}

	validConf := monitoringv1beta1.AlertmanagerConfig{}
	err = yaml.Unmarshal([]byte(validAmConf), &validConf)
	if err != nil {
		t.Fatal("unable to unmarshal alertmanagerconfig", err)
	}
	_, err = f.MonitoringBetaClient.AlertmanagerConfigs(f.Ns).Create(ctx, &validConf, metav1.CreateOptions{})
	if err != nil {
		t.Fatal("unable to create alertmanagerconfig", err)
	}

	invalidConf := monitoringv1beta1.AlertmanagerConfig{}
	err = yaml.Unmarshal([]byte(invalidAmConf), &invalidConf)
	if err != nil {
		t.Fatal("unable to unmarshal alertmanagerconfig", err)
	}
	_, err = f.MonitoringBetaClient.AlertmanagerConfigs(f.Ns).Create(ctx, &invalidConf, metav1.CreateOptions{})
	if err == nil {
		t.Fatal("invalid alertmanagerconfig was accepted by validatingwebhook")
	}
}
