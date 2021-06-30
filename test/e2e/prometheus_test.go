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
	"fmt"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPrometheusMetrics(t *testing.T) {
	for service, expected := range map[string]int{
		"prometheus-operator":           1,
		"prometheus-k8s":                2,
		"prometheus-k8s-thanos-sidecar": 2,
		"thanos-querier":                2,
		"prometheus-adapter":            2,
		"alertmanager-main":             3,
		"kube-state-metrics":            2, // one for the kube metrics + one for the metrics of the process itself.
		"openshift-state-metrics":       2, // ditto.
		"telemeter-client":              1,
		"grafana":                       1,
	} {
		t.Run(service, func(t *testing.T) {
			f.ThanosQuerierClient.WaitForQueryReturn(
				t, 10*time.Minute, fmt.Sprintf(`count(up{service="%s",namespace="openshift-monitoring"} == 1)`, service),
				func(i int) error {
					if i != expected {
						return fmt.Errorf("expected %d targets to be up but got %d", expected, i)
					}

					return nil
				},
			)
		})
	}
}

func TestPrometheusAlertmanagerAntiAffinity(t *testing.T) {
	pods, err := f.KubeClient.CoreV1().Pods(f.Ns).List(f.Ctx, metav1.ListOptions{FieldSelector: "status.phase=Running"})
	if err != nil {
		t.Fatal(err)
	}

	var (
		testPod1      = "alertmanager-main"
		testPod2      = "prometheus-k8s"
		testNameSpace = "openshift-monitoring"

		almOk = false
		k8sOk = false
	)

	for _, p := range pods.Items {
		if strings.Contains(p.Namespace, testNameSpace) &&
			strings.Contains(p.Name, testPod1) {
			if p.Spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution != nil {
				almOk = true
			} else {
				t.Fatal("Failed to find preferredDuringSchedulingIgnoredDuringExecution in alertmanager pod spec")
			}
		}

		if strings.Contains(p.Namespace, testNameSpace) &&
			strings.Contains(p.Name, testPod2) {
			if p.Spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution != nil {
				k8sOk = true
			} else {
				t.Fatal("Failed to find preferredDuringSchedulingIgnoredDuringExecution in prometheus pod spec")
			}
		}
	}

	if !almOk == true || !k8sOk == true {
		t.Fatal("Can not find pods: prometheus-k8s or alertmanager-main")
	}
}
