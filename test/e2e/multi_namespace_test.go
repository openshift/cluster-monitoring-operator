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
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestMultinamespacePrometheusRule(t *testing.T) {
	ctx := context.Background()
	nsName := "openshift-test-prometheus-rules" + strconv.FormatInt(time.Now().Unix(), 36)
	t.Parallel()

	t.Cleanup(func() {
		f.OperatorClient.DeleteIfExists(ctx, nsName)
	})

	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
			Labels: map[string]string{
				"openshift.io/cluster-monitoring": "true",
				framework.E2eTestLabelName:        framework.E2eTestLabelValue,
			},
		},
	}
	_, err := f.KubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	err = f.OperatorClient.CreateOrUpdatePrometheusRule(ctx, &monv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-monitoring-prometheus-rules",
			Namespace: nsName,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
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
		t.Fatal(err)
	}

	// wait for proxies bootstrap
	err = framework.Poll(time.Second, 5*time.Minute, func() error {
		_, err := f.ThanosQuerierClient.Do("GET", "/-/ready", nil)
		if err != nil {
			return errors.Wrap(err, "establishing connection to thanos proxy failed")
		}
		return nil
	})

	if err != nil {
		t.Fatal(err)
	}

	f.ThanosQuerierClient.WaitForQueryReturnOne(
		t,
		10*time.Minute,
		`count(ALERTS{alertname="AdditionalTestAlertRule"} == 1)`,
	)
}
