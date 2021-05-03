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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
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

func TestPrometheusVolumeClaim(t *testing.T) {
	err := f.OperatorClient.WaitForStatefulsetRollout(&appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus-k8s",
			Namespace: f.Ns,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-monitoring-config",
			Namespace: f.Ns,
		},
		Data: map[string]string{
			"config.yaml": `prometheusK8s:
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: 2Gi
`,
		},
	}

	if err := f.OperatorClient.CreateOrUpdateConfigMap(cm); err != nil {
		t.Fatal(err)
	}

	err = framework.Poll(time.Second, 5*time.Minute, func() error {
		_, err := f.KubeClient.CoreV1().PersistentVolumeClaims(f.Ns).Get(context.TODO(), "prometheus-k8s-db-prometheus-k8s-0", metav1.GetOptions{})
		if err != nil {
			return errors.Wrap(err, "getting prometheus persistent volume claim failed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	err = f.OperatorClient.WaitForStatefulsetRollout(&appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus-k8s",
			Namespace: f.Ns,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPrometheusAlertmanagerAntiAffinity(t *testing.T) {
	pods, err := f.KubeClient.CoreV1().Pods(f.Ns).List(context.TODO(), metav1.ListOptions{FieldSelector: "status.phase=Running"})
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
			if p.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
				k8sOk = true
			} else {
				t.Fatal("Failed to find requiredDuringSchedulingIgnoredDuringExecution in prometheus pod spec")
			}
		}
	}

	if !almOk == true || !k8sOk == true {
		t.Fatal("Can not find pods: prometheus-k8s or alertmanager-main")
	}
}
