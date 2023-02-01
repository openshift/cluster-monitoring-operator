// Copyright 2022 The Cluster Monitoring Operator Authors
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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNodeExporterCollectorEnablement(t *testing.T) {
	t.Cleanup(func() {
		f.MustDeleteConfigMap(t, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterMonitorConfigMapName,
				Namespace: f.Ns,
			},
		})
	})

	f.PrometheusK8sClient.WaitForQueryReturn(
		t, 5*time.Minute, `absent(node_scrape_collector_success{collector="cpufreq"})`,
		func(v float64) error {
			if v == 1 {
				return nil
			}
			return fmt.Errorf("expecting absent(node_scrape_collector_success{collector=\"cpufreq\"}) = 1 but got %v.", v)
		},
	)

	data := `nodeExporter:
  collectors:
    cpufreq:
      enabled: true
`
	f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, data))

	f.PrometheusK8sClient.WaitForQueryReturn(
		t, 5*time.Minute, `min(node_scrape_collector_success{collector="cpufreq"})`,
		func(v float64) error {
			if v == 0 {
				return fmt.Errorf("expecting min(node_scrape_collector_success{collector=\"cpufreq\"})> 0 but got %v.", v)
			}
			return nil
		},
	)
}
