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
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

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
      storageClassName: gp2
      resources:
        requests:
          storage: 2Gi
`,
		},
	}

	if err := f.OperatorClient.CreateOrUpdateConfigMap(cm); err != nil {
		t.Fatal(err)
	}

	var lastErr error
	// Wait for persistent volume claim
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		_, err := f.KubeClient.CoreV1().PersistentVolumeClaims(f.Ns).Get("prometheus-k8s-db-prometheus-k8s-0", metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting prometheus persistent volume claim failed")
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
	pods, err := f.KubeClient.CoreV1().Pods(f.Ns).List(metav1.ListOptions{FieldSelector: "status.phase=Running"})
	if err != nil {
		t.Fatal(err)
	}

	var alm = `affinity:
	   podAntiAffinity:
	      preferredDuringSchedulingIgnoredDuringExecution:
	      - podAffinityTerm:
	          labelSelector:
	            matchExpressions:
	            - key: alertmanager
	              operator: In
	              values:
	              - main`

	var k8s = `affinity:
	   podAntiAffinity:
	      preferredDuringSchedulingIgnoredDuringExecution:
	      - podAffinityTerm:
	          labelSelector:
	            matchExpressions:
	            - key: prometheus
	              operator: In
	              values:
	              - k8s`

	var (
		testPod1      = "alertmanager-main"
		testPod2      = "prometheus-k8s"
		testNameSpace = "openshift-monitoring"

		podA  = strings.ToLower(alm[14:28])
		prefA = strings.ToLower(alm[38:85])
		keyA  = strings.ToLower(alm[190:202])
		valA  = strings.ToLower(alm[271:275])

		podB  = strings.ToLower(k8s[14:28])
		prefB = strings.ToLower(k8s[38:85])
		keyB  = strings.ToLower(k8s[190:200])
		valB  = strings.ToLower(k8s[269:272])

		almOk = false
		k8sOk = false
	)

	for _, p := range pods.Items {
		if strings.Contains(p.Namespace, testNameSpace) &&
			strings.Contains(p.Name, testPod1) {
			outputPodAntiAffinity := strings.ToLower(
				p.Spec.Affinity.PodAntiAffinity.String())
			if strings.Contains(outputPodAntiAffinity, podA) &&
				strings.Contains(outputPodAntiAffinity, prefA) &&
				strings.Contains(outputPodAntiAffinity, keyA) &&
				strings.Contains(outputPodAntiAffinity, valA) {
				almOk = true
			} else {
				t.Fatal("Can not find podAntiAffinity config line or wrong order (1).")
			}
		}

		if strings.Contains(p.Namespace, testNameSpace) &&
			strings.Contains(p.Name, testPod2) {
			outputPodAntiAffinity := strings.ToLower(
				p.Spec.Affinity.PodAntiAffinity.String())
			if strings.Contains(outputPodAntiAffinity, podB) &&
				strings.Contains(outputPodAntiAffinity, prefB) &&
				strings.Contains(outputPodAntiAffinity, keyB) &&
				strings.Contains(outputPodAntiAffinity, valB) {
				k8sOk = true
			} else {
				t.Fatal("Can not find podAntiAffinity config line or wrong order (2).")
			}
		}
	}

	if !almOk == true || !k8sOk == true {
		t.Fatal("Can not find pods: prometheus-k8s or alertmanager-main")
	}
}

func TestPrometheusMetricsBestPractice(t *testing.T) {
	metrics, err := f.PrometheusK8sClient.PrometheusGetMetrics()
	if err != nil {
		t.Fatalf("Could not get Prometheus metrics: %v", err)
	}

	cmd := exec.Command(f.PromtoolBin,
		"check",
		"metrics",
	)
	cmd.Stdin = bytes.NewReader(metrics)

	out, err := cmd.CombinedOutput()
	t.Logf("%s:\n%s", cmd, out)
	if err != nil {
		t.Fatalf("Executing %s: %v", cmd, err)
	}
}

func TestPrometheusRulesBestPractice(t *testing.T) {
	rawRules, err := f.PrometheusK8sClient.PrometheusGetRules()
	if err != nil {
		t.Fatalf("Could not get Prometheus rules: %v", err)
	}

	rulesManifest := ".prometheus-rules.yaml"
	err = framework.CreatePrometheusRulesManifest(rulesManifest, rawRules)
	if err != nil {
		t.Fatalf("Could not create manifest from Prometheus rules raw data: %v", err)
	}
	defer os.Remove(rulesManifest)

	cmd := exec.Command(f.PromtoolBin,
		"check",
		"rules",
		rulesManifest,
	)
	out, err := cmd.CombinedOutput()
	t.Logf("%s:\n%s", cmd, out)
	if err != nil {
		t.Fatalf("Executing %s: %v", cmd, err)
	}
}
