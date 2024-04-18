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
	"errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"regexp"
	"testing"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
)

func TestKSMMetricsSuppression(t *testing.T) {

	suppressedPattern, _ := regexp.Compile("kube_.*_annotations")

	err := framework.Poll(5*time.Second, time.Minute, func() error {

		client := f.PrometheusK8sClient

		b, err := client.PrometheusLabel("__name__")
		if err != nil {
			return err
		}

		response, err := gabs.ParseJSON(b)
		if err != nil {
			return err
		}

		status, ok := response.Path("status").Data().(string)
		if !ok {
			return errors.New("status not found")
		}

		if status != "success" {
			t.Errorf("Prometheus returned unexpected status: %s", status)
		}

		for _, name := range response.Search("data").Children() {
			metricName := name.Data().(string)
			if suppressedPattern.Match([]byte(metricName)) {
				t.Errorf("Metric should be suppressed: %s", metricName)
			}
		}

		return nil
	})
	if err != nil {
		t.Errorf("failed to query Prometheus: %v", err)
	}

}

func TestKSMDenylistBoundsCheck(t *testing.T) {

	// Update CMO config to include an invalid deny-list.
	cfg, err := getOrCreateCMOConfig(t)
	if err != nil {
		t.Errorf("failed to get cluster-monitoring-config configmap: %v", err)
	}
	cfgCopy := cfg.DeepCopy()
	invalidMetricExpression := "^kube_lease_owner$"
	cfg.Data = map[string]string{
		"config.yaml": `
kubeStateMetrics:
  metricDenylist:
    - ` + invalidMetricExpression,
	}
	_, err = f.KubeClient.CoreV1().ConfigMaps(operatorNamespace).Update(ctx, cfg, metav1.UpdateOptions{})
	if err != nil {
		t.Errorf("failed to update cluster-monitoring-config configmap: %v", err)
	}

	// Check KSM deployment for the default deny-list.
	if err = expectMetricInDenylist(t, false, invalidMetricExpression); err != nil {
		t.Fatalf("deny-list unexpected error: %v", err)
	}

	// Update CMO config to include a valid deny-list.
	cfg, err = getOrCreateCMOConfig(t)
	if err != nil {
		t.Errorf("failed to get cluster-monitoring-config configmap: %v", err)
	}
	validMetricExpression := "^kube_.+_annotations$"
	cfg.Data = map[string]string{
		"config.yaml": `
kubeStateMetrics:
  metricDenylist:
    - ` + validMetricExpression,
	}
	_, err = f.KubeClient.CoreV1().ConfigMaps(operatorNamespace).Update(ctx, cfg, metav1.UpdateOptions{})
	if err != nil {
		t.Errorf("failed to update cluster-monitoring-config configmap: %v", err)
	}

	// Check KSM deployment for the updated deny-list.
	if err = expectMetricInDenylist(t, true, validMetricExpression); err != nil {
		t.Fatalf("deny-list unexpected error: %v", err)
	}

	// Update CMO config to include a valid deny-list again, but to make sure the default list is respected even if the
	// last deny-list wasn't the default one.
	cfg, err = getOrCreateCMOConfig(t)
	if err != nil {
		t.Errorf("failed to get cluster-monitoring-config configmap: %v", err)
	}
	validDefaultMetricExpression := "^kube_replicaset_metadata_generation$"
	cfg.Data = map[string]string{
		"config.yaml": `
kubeStateMetrics:
  metricDenylist:
    - ` + validDefaultMetricExpression,
	}
	_, err = f.KubeClient.CoreV1().ConfigMaps(operatorNamespace).Update(ctx, cfg, metav1.UpdateOptions{})
	if err != nil {
		t.Errorf("failed to update cluster-monitoring-config configmap: %v", err)
	}

	// Check KSM deployment for the updated deny-list.
	if err = expectMetricInDenylist(t, true, validDefaultMetricExpression); err != nil {
		t.Fatalf("deny-list unexpected error: %v", err)
	}

	// Revert CMO config to the original state.
	cfg, err = getOrCreateCMOConfig(t)
	if err != nil {
		t.Errorf("failed to get cluster-monitoring-config configmap: %v", err)
	}
	cfg.Data = cfgCopy.Data
	_, err = f.KubeClient.CoreV1().ConfigMaps(operatorNamespace).Update(ctx, cfg, metav1.UpdateOptions{})
	if err != nil {
		t.Errorf("failed to update cluster-monitoring-config configmap: %v", err)
	}
}

func expectMetricInDenylist(t *testing.T, expect bool, metric string) error {
	t.Helper()

	return framework.Poll(5*time.Second, time.Minute, func() error {
		d, err := f.KubeClient.AppsV1().Deployments(operatorNamespace).Get(ctx, "kube-state-metrics", metav1.GetOptions{})
		if err != nil {
			return err
		}

		for _, c := range d.Spec.Template.Spec.Containers {
			if c.Name == "kube-state-metrics" {
				for _, a := range c.Args {
					if a == "--metric-denylist="+metric {
						if !expect {
							return errors.New("deny-list should not have been found in kube-state-metrics deployment")
						}
						return nil
					}
				}
			}
		}

		if expect {
			return errors.New("denylist not found in kube-state-metrics deployment")
		}
		return nil
	})

}
