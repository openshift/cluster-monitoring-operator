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
	"testing"

	yaml "github.com/ghodss/yaml"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	webhookName = "prometheusrules.openshift.io"
)

var (
	validPromRuleYaml = `---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: valid-rule
spec:
  groups:
  - name: recording-rules
    rules:
    - record: my_always_record_one
      expr: 1
`

	invalidPromRuleYaml = `---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: invalid-rule
spec:
  groups:
  - name: invalid-rule-group
    rules:
    - record: invalid_rule
      expr: this+/(fails
`
)

func TestPrometheusRuleValidatingWebhook(t *testing.T) {
	_, err := f.AdmissionClient.ValidatingWebhookConfigurations().Get(context.TODO(), webhookName, metav1.GetOptions{})
	if err != nil {
		t.Fatal("unable to get prometheus rules validating webhook", err)
	}

	validPromRule := monitoringv1.PrometheusRule{}
	err = yaml.Unmarshal([]byte(validPromRuleYaml), &validPromRule)
	if err != nil {
		t.Fatal("unable to unmarshal prometheus rule", err)
	}
	_, err = f.MonitoringClient.PrometheusRules(f.Ns).Create(context.TODO(), &validPromRule, metav1.CreateOptions{})
	if err != nil {
		t.Fatal("unable to create prometheus rule", err)
	}

	invalidPromRule := monitoringv1.PrometheusRule{}
	err = yaml.Unmarshal([]byte(invalidPromRuleYaml), &invalidPromRule)
	if err != nil {
		t.Fatal("unable to unmarshal prometheus rule", err)
	}
	_, err = f.MonitoringClient.PrometheusRules(f.Ns).Create(context.TODO(), &invalidPromRule, metav1.CreateOptions{})
	if err == nil {
		t.Fatal("invalid rule was accepted by validatingwebhook")
	}

}
