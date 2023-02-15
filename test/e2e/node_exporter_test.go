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

	tests := []struct {
		nameCollector string
		config        string
	}{
		{
			nameCollector: "cpufreq",
			config: `
nodeExporter:
  collectors:
    cpufreq:
      enabled: true`,
		},
		{
			nameCollector: "tcpstat",
			config: `
nodeExporter:
  collectors:
    tcpstat:
      enabled: true`,
		},
		{
			nameCollector: "buddyinfo",
			config: `
nodeExporter:
  collectors:
    buddyinfo:
      enabled: true`,
		},
	}

	for _, test := range tests {
		t.Run("Enable Collector: "+test.nameCollector, func(st *testing.T) {
			f.PrometheusK8sClient.WaitForQueryReturn(
				t, 5*time.Minute, fmt.Sprintf(`absent(node_scrape_collector_success{collector="%s"})`, test.nameCollector),
				func(v float64) error {
					if v == 1 {
						return nil
					}
					return fmt.Errorf(`expecting absent(node_scrape_collector_success{collector="%s"}) = 1 but got %v.`, test.nameCollector, v)
				},
			)

			f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, test.config))

			f.PrometheusK8sClient.WaitForQueryReturn(
				t, 5*time.Minute, fmt.Sprintf(`min(node_scrape_collector_success{collector="%s"})`, test.nameCollector),
				func(v float64) error {
					if v == 0 {
						return fmt.Errorf(`expecting min(node_scrape_collector_success{collector="%s"})> 0 but got %v.`, test.nameCollector, v)
					}
					return nil
				},
			)
		})
	}

}

func TestNodeExporterCollectorDisablement(t *testing.T) {
	t.Cleanup(func() {
		f.MustDeleteConfigMap(t, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterMonitorConfigMapName,
				Namespace: f.Ns,
			},
		})
	})

	tests := []struct {
		nameCollector string
		config        string
		metrics       []string
	}{
		{
			nameCollector: "netdev",
			config: `
nodeExporter:
  collectors:
    netdev:
      enabled: false`,
			metrics: []string{
				"node_network_receive_bytes_total",
				"node_network_receive_compressed_total",
				"node_network_receive_drop_total",
				"node_network_receive_errs_total",
				"node_network_receive_fifo_total",
				"node_network_receive_frame_total",
				"node_network_receive_multicast_total",
				"node_network_receive_nohandler_total",
				"node_network_receive_packets_total",
				"node_network_transmit_bytes_total",
				"node_network_transmit_carrier_total",
				"node_network_transmit_colls_total",
				"node_network_transmit_compressed_total",
				"node_network_transmit_drop_total",
				"node_network_transmit_errs_total",
				"node_network_transmit_fifo_total",
				"node_network_transmit_packets_total",
			},
		},
		{
			nameCollector: "netclass",
			config: `
nodeExporter:
  collectors:
    netclass:
      enabled: false`,
			metrics: []string{
				"node_network_carrier",
				"node_network_carrier_changes_total",
				"node_network_carrier_down_changes_total",
				"node_network_carrier_up_changes_total",
				"node_network_dormant",
				"node_network_flags",
				"node_network_iface_id",
				"node_network_iface_link",
				"node_network_iface_link_mode",
				"node_network_info",
				"node_network_mtu_bytes",
				"node_network_net_dev_group",
				"node_network_protocol_type",
				"node_network_speed_bytes",
				"node_network_transmit_queue_length",
				"node_network_up",
			},
		},
	}

	for _, test := range tests {
		t.Run("Disable Collector: "+test.nameCollector, func(st *testing.T) {
			f.PrometheusK8sClient.WaitForQueryReturn(
				t, 5*time.Minute, fmt.Sprintf(`min(node_scrape_collector_success{collector="%s"})`, test.nameCollector),
				func(v float64) error {
					if v == 1 {
						return nil
					}
					return fmt.Errorf(`expecting min(node_scrape_collector_success{collector="%s"}) = 1 but got %v.`, test.nameCollector, v)
				},
			)

			for _, metric := range test.metrics {
				f.PrometheusK8sClient.WaitForQueryReturnEmpty(t, 5*time.Minute, fmt.Sprintf(`absent(%s)`, metric))
			}

			f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, test.config))

			f.PrometheusK8sClient.WaitForQueryReturn(
				t, 5*time.Minute, fmt.Sprintf(`absent_over_time(node_scrape_collector_success{collector="%s"}[1m])`, test.nameCollector),
				func(v float64) error {
					if v == 0 {
						return fmt.Errorf(`expecting absent_over_time(node_scrape_collector_success{collector="%s"}[1m])> 0 but got %v.`, test.nameCollector, v)
					}
					return nil
				},
			)
		})
	}
}

// This test ensures neccessary collectors stay operational after changing generic options in Node Exporter.
func TestNodeExporterGenericOptions(t *testing.T) {
	t.Cleanup(func() {
		f.MustDeleteConfigMap(t, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterMonitorConfigMapName,
				Namespace: f.Ns,
			},
		})
	})

	collectorsToCheck := []string{
		"cpu",
		"diskstats",
		"filesystem",
		"hwmon",
		"loadavg",
		"meminfo",
		"netclass",
		"netdev",
		"netstat",
		"os",
		"stat",
		"time",
		"uname",
		"vmstat",
	}

	tests := []struct {
		name        string
		config      string
		argsPresent []string
	}{
		{
			name:   "default config",
			config: "",
		},
		{
			name: "maxprocs = 1",
			config: `
nodeExporter:
  maxProcs: 1`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(st *testing.T) {
			f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, test.config))

			for _, nameCollector := range collectorsToCheck {

				f.PrometheusK8sClient.WaitForQueryReturn(
					t, 5*time.Minute, fmt.Sprintf(`min(node_scrape_collector_success{collector="%s"})`, nameCollector),
					func(v float64) error {
						if v != 1 {
							return fmt.Errorf(`expecting min(node_scrape_collector_success{collector="%s"}) = 1 but got %v.`, nameCollector, v)
						}
						return nil
					},
				)
			}
		})
	}

}
