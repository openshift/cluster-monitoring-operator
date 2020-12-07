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

	"github.com/pkg/errors"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
)

func TestMultinamespacePrometheusRule(t *testing.T) {
	t.Parallel()

	nsName := "openshift-test-prometheus-rules" + strconv.FormatInt(time.Now().Unix(), 36)
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
			Labels: map[string]string{
				"openshift.io/cluster-monitoring": "true",
			},
		},
	}
	_, err := f.KubeClient.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer f.OperatorClient.DeleteIfExists(nsName)

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
		t.Fatal(err)
	}

	var lastErr error
	// wait for proxies bootstrap
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		_, err := f.ThanosQuerierClient.Do("GET", "/-/ready", nil)
		lastErr = errors.Wrap(err, "establishing connection to thanos proxy failed")
		if err != nil {
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		t.Fatal(err)
	}

	f.ThanosQuerierClient.WaitForQueryReturnOne(
		t,
		10*time.Minute,
		`count(ALERTS{alertname="AdditionalTestAlertRule"} == 1)`,
	)
}
