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
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/stretchr/testify/require"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMultinamespacePrometheusRule(t *testing.T) {
	// The test shouldn't be disruptive, safe to run in parallel with others.
	t.Parallel()
	nsName := "openshift-test-prometheus-rules"
	firingAlertName := "FiringAlertInNamespace"

	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
			Labels: map[string]string{
				"openshift.io/cluster-monitoring": "true",
				framework.E2eTestLabelName:        framework.E2eTestLabelValue,
			},
		},
	}
	_, err := f.KubeClient.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		f.DeleteNamespace(t, nsName)
	})

	createPrometheusRuleWithAlert(t, nsName, "non-monitoring-prometheus-rules", firingAlertName)

	for _, check := range []struct {
		name string
		f    func(*testing.T)
	}{
		{
			name: "the alert was taken into account by Thanos",
			f: func(t *testing.T) {
				f.ThanosQuerierClient.WaitForQueryReturnOne(
					t,
					5*time.Minute,
					fmt.Sprintf(`count(ALERTS{alertname="%s"} == 1)`, firingAlertName),
				)
			},
		},
		{
			name: "the alert has the default platform labels in Alertmanager",
			f: func(t *testing.T) {
				checkAlertHasPlatformLabels(t, firingAlertName)
			},
		},
	} {
		t.Run(check.name, func(t *testing.T) {
			t.Parallel()
			check.f(t)
		})
	}

}

func checkAlertHasPlatformLabels(t *testing.T, alertName string) {
	const (
		expectPlatformLabel      = "openshift_io_alert_source"
		expectPlatformLabelValue = "platform"
	)

	type Alerts []struct {
		Labels map[string]string `json:"labels"`
	}

	var alerts Alerts

	err := framework.Poll(5*time.Second, 5*time.Minute, func() error {
		body, err := f.AlertmanagerClient.GetAlertmanagerAlerts(
			"filter", fmt.Sprintf(`alertname="%s"`, alertName),
			"active", "true",
		)
		if err != nil {
			return err
		}

		if err = json.Unmarshal(body, &alerts); err != nil {
			return err
		}

		if len(alerts) != 1 {
			return fmt.Errorf("couldn't find the firing alert")
		}

		return nil
	})
	require.NoError(t, err)
	require.Subset(t, alerts[0].Labels, map[string]string{expectPlatformLabel: expectPlatformLabelValue})
}
