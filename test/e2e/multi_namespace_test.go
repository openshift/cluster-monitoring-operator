// Copyright 2019 The Cluster Monitoring Operator Authors
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
	"log"
	"testing"

	monv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestMultinamespacePrometheusRule(t *testing.T) {
	t.Parallel()

	nsName := "openshift-test-prometheus-rules"

	err := f.OperatorClient.CreateOrUpdateNamespace(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
			Labels: map[string]string{
				"openshift.io/cluster-monitoring": "true",
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	err = f.OperatorClient.CreateOrUpdatePrometheusRule(&monv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-monitoring-prometheus-rules",
			Namespace: nsName,
		},
		Spec: monv1.PrometheusRuleSpec{
			Groups: []monv1.RuleGroup{
				{
					Name: "test-group",
					Rules: []monv1.Rule{
						{
							Alert: "AdditionalTestAlertRule",
							Expr:  intstr.FromString("vector(1)"),
						},
					},
				},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	RunTestQueries(t, []Query{
		{
			Query:   `ALERTS{alertname="AdditionalTestAlertRule"} == 1`,
			ExpectN: 1,
		},
	})
}
