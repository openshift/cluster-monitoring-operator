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
	"time"

	"github.com/pkg/errors"
	"k8s.io/api/apps/v1beta2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

func TestPrometheusVolumeClaim(t *testing.T) {
	err := f.OperatorClient.WaitForStatefulsetRollout(&v1beta2.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus-k8s",
			Namespace: f.Ns,
		},
	})
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
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
		log.Fatal(err)
	}

	err = f.OperatorClient.WaitForStatefulsetRollout(&v1beta2.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus-k8s",
			Namespace: f.Ns,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}

func TestPrometheusOnlyFiringWatchdogAlert(t *testing.T) {
	f.PrometheusK8sClient.WaitForQueryReturnOne(
		t,
		time.Minute,
		`count(ALERTS{alertstate="firing"} == 1)`,
	)

	f.PrometheusK8sClient.WaitForQueryReturnOne(
		t,
		time.Minute,
		`count(ALERTS{alertname="Watchdog",alertstate="firing"} == 1)`,
	)
}
