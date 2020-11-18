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
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
)

func TestClusterMonitoringOperatorConfiguration(t *testing.T) {
	// Enable user workload monitoring to assess that an invalid configuration
	// doesn't rollback the last known and valid configuration.
	validCM := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-monitoring-config",
			Namespace: f.Ns,
		},
		Data: map[string]string{
			"config.yaml": `enableUserWorkload: true
`,
		},
	}

	if err := f.OperatorClient.CreateOrUpdateConfigMap(validCM); err != nil {
		t.Fatal(err)
	}

	err := framework.Poll(time.Second, 5*time.Minute, func() error {
		_, err := f.KubeClient.AppsV1().StatefulSets(f.UserWorkloadMonitoringNs).Get(context.TODO(), "prometheus-user-workload", metav1.GetOptions{})
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("asserting that CMO is healthy")
	assertOperatorCondition(t, configv1.OperatorDegraded, configv1.ConditionFalse)
	assertOperatorCondition(t, configv1.OperatorAvailable, configv1.ConditionTrue)

	// Push an invalid configuration.
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-monitoring-config",
			Namespace: f.Ns,
		},
		Data: map[string]string{
			"config.yaml": `cannot be deserialized`,
		},
	}

	if err := f.OperatorClient.CreateOrUpdateConfigMap(cm); err != nil {
		t.Fatal(err)
	}

	t.Log("asserting that CMO goes degraded after an invalid configuration is pushed")
	assertOperatorCondition(t, configv1.OperatorDegraded, configv1.ConditionTrue)
	assertOperatorCondition(t, configv1.OperatorAvailable, configv1.ConditionFalse)
	// Check that the previous setup hasn't been reverted
	_, err = f.KubeClient.AppsV1().StatefulSets(f.UserWorkloadMonitoringNs).Get(context.TODO(), "prometheus-user-workload", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Restore the first configuration.
	if err := f.OperatorClient.CreateOrUpdateConfigMap(validCM); err != nil {
		t.Fatal(err)
	}

	t.Log("asserting that CMO goes back healthy after the configuration is fixed")
	assertOperatorCondition(t, configv1.OperatorDegraded, configv1.ConditionFalse)
	assertOperatorCondition(t, configv1.OperatorAvailable, configv1.ConditionTrue)
}

func assertOperatorCondition(t *testing.T, conditionType configv1.ClusterStatusConditionType, conditionStatus configv1.ConditionStatus) {
	t.Helper()

	reporter := f.OperatorClient.StatusReporter()
	err := framework.Poll(time.Second, 5*time.Minute, func() error {
		co, err := reporter.Get()
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range co.Status.Conditions {
			if c.Type == conditionType {
				if c.Status == conditionStatus {
					return nil
				}
				return errors.Errorf("expecting condition %q to be %q, got %q", conditionType, conditionStatus, c.Status)
			}
		}
		return errors.Errorf("failed to find condition %q", conditionType)
	})
	if err != nil {
		t.Fatal(err)
	}
}
