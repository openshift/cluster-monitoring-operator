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
)

func TestNodeExporterCollectorEnablement(t *testing.T) {
	t.Cleanup(func() {
		f.MustDeleteConfigMap(t, f.BuildCMOConfigMap(t, ""))
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
		{
			nameCollector: "mountstats",
			config: `
nodeExporter:
  collectors:
    mountstats:
      enabled: true`,
		},
		{
			nameCollector: "ksmd",
			config: `
nodeExporter:
  collectors:
    ksmd:
      enabled: true`,
		},
		{
			nameCollector: "processes",
			config: `
nodeExporter:
  collectors:
    processes:
      enabled: true`,
		},
		{
			nameCollector: "systemd",
			config: `
nodeExporter:
  collectors:
    systemd:
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

			f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, test.config))

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
		f.MustDeleteConfigMap(t, f.BuildCMOConfigMap(t, ""))
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

			f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, test.config))

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

// This test ensures necessary collectors stay operational after changing generic options in Node Exporter.
func TestNodeExporterGenericOptions(t *testing.T) {
	t.Cleanup(func() {
		f.MustDeleteConfigMap(t, f.BuildCMOConfigMap(t, ""))
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
			f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, test.config))

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

func TestNodeExporterNetworkDevicesExclusion(t *testing.T) {
	t.Cleanup(func() {
		f.MustDeleteConfigMap(t, f.BuildCMOConfigMap(t, ""))
	})

	tests := []struct {
		name      string
		config    string
		filter    string
		mustExist bool
	}{
		{
			name:      "default devices generate metrics",
			mustExist: true,
		},
		{
			name:      "default devices include 'lo'",
			filter:    `device="lo"`,
			mustExist: true,
		},
		{
			name: "excluding 'lo'",
			config: `
nodeExporter:
  ignoredNetworkDevices:
  - lo`,
			filter:    `device="lo"`,
			mustExist: false,
		},
		{
			name: "excluding all",
			config: `
nodeExporter:
  ignoredNetworkDevices:
  - .*`,
			mustExist: false,
		},
	}

	for _, test := range tests {
		t.Run("Network Devices Exclusion: "+test.name, func(st *testing.T) {
			f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, test.config))
			q := fmt.Sprintf(`sum(rate(node_network_receive_bytes_total{%s}[30s]))`, test.filter)
			if test.mustExist {
				f.PrometheusK8sClient.WaitForQueryReturn(
					t, 5*time.Minute, q,
					func(v float64) error {
						if v > 0 {
							return nil
						}
						return fmt.Errorf(`test %s failed, expecting query '%s' to return a positive value, got: %v.`, test.name, q, v)
					},
				)
			} else {
				f.PrometheusK8sClient.WaitForQueryReturnEmpty(t, 5*time.Minute, fmt.Sprintf(`absent(%s)`, q))
			}
		})
	}
}

func TestNodeExporterSystemdUnits(t *testing.T) {
	t.Cleanup(func() {
		f.MustDeleteConfigMap(t, f.BuildCMOConfigMap(t, ""))
	})
	configNoUnits := `
nodeExporter:
  collectors:
    systemd:
      enabled: true
`

	t.Run("default without units", func(st *testing.T) {
		f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, configNoUnits))

		// Systemd collector should be enabled.
		f.PrometheusK8sClient.WaitForQueryReturn(
			t, 5*time.Minute, `min(node_scrape_collector_success{collector="systemd"})`,
			func(v float64) error {
				if v != 1 {
					return fmt.Errorf(`expecting min(node_scrape_collector_success{collector="systemd"}) 1 but got %v.`, v)
				}
				return nil
			},
		)

		// Systemd collector should not collect unit state.
		f.PrometheusK8sClient.WaitForQueryReturn(
			t, 5*time.Minute, `absent(node_systemd_unit_state)`,
			func(v float64) error {
				if v != 1 {
					return fmt.Errorf(`expecting absent(node_systemd_unit_state) = 1 but got %v.`, v)
				}
				return nil
			},
		)

	})
	configWithUnits := `
nodeExporter:
  collectors:
    systemd:
      enabled: true
      units:
      - network.+
      - nss.+
`

	t.Run("enabled with units", func(st *testing.T) {
		f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, configWithUnits))

		// Systemd collector should be enabled.
		f.PrometheusK8sClient.WaitForQueryReturn(
			t, 5*time.Minute, `min(node_scrape_collector_success{collector="systemd"})`,
			func(v float64) error {
				if v != 1 {
					return fmt.Errorf(`expecting min(node_scrape_collector_success{collector="systemd"}) 1 but got %v.`, v)
				}
				return nil
			},
		)

		// Systemd collector should collect unit state.
		// One node_systemd_unit_state metric should be 1 while the rest should be 0 for each unit.
		f.PrometheusK8sClient.WaitForQueryReturn(
			t, 5*time.Minute, `max(node_systemd_unit_state)`,
			func(v float64) error {
				if v != 1 {
					return fmt.Errorf(`expecting max(node_systemd_unit_state) = 1 but got %v.`, v)
				}
				return nil
			},
		)

	})

}
