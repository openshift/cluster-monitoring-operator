// Copyright 2018 The Cluster Monitoring Operator Authors
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

package manifests

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"
)

func TestConfigParsing(t *testing.T) {
	f, err := os.Open("../../examples/config/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	if c.ClusterMonitoringConfiguration.AlertmanagerMainConfig.VolumeClaimTemplate == nil {
		t.Fatal("config parsing failed: AlertmanagerMainConfig VolumeClaimTemplate was not parsed correctly")
	}
}

func TestNewUserConfigFromStringParsing(t *testing.T) {
	c, err := ioutil.ReadFile("../../examples/user-workload/configmap.yaml")
	if err != nil {
		t.Fatal(err)
	}

	uwmc, err := NewUserConfigFromString(string(c))
	if err != nil {
		t.Fatal(err)
	}

	if uwmc.PrometheusOperator == nil {
		t.Fatal("config parsing failed: Prometheus Operator was not parsed correctly")
	}
	if uwmc.Prometheus == nil {
		t.Fatal("config parsing failed: Prometheus was not parsed correctly")
	}
	if uwmc.ThanosRuler == nil {
		t.Fatal("config parsing failed: Thanos was not parsed correctly")
	}
}

func TestEmptyConfigIsValid(t *testing.T) {
	_, err := NewConfigFromString("")
	if err != nil {
		t.Fatal(err)
	}
}

func TestEmptyUserConfigIsValid(t *testing.T) {
	_, err := NewUserConfigFromString("")
	if err != nil {
		t.Fatal(err)
	}
}

func TestTelemeterClientConfig(t *testing.T) {
	truev, falsev := true, false

	tcs := []struct {
		enabled bool
		cfg     *TelemeterClientConfig
	}{
		{
			cfg:     nil,
			enabled: false,
		},
		{
			cfg:     &TelemeterClientConfig{},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				Enabled: &truev,
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				Enabled: &falsev,
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				ClusterID: "test",
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				ClusterID: "test",
				Enabled:   &falsev,
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				ClusterID: "test",
				Enabled:   &truev,
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				Token: "test",
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				Token:   "test",
				Enabled: &falsev,
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				Token:   "test",
				Enabled: &truev,
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				ClusterID: "test",
				Token:     "test",
			},
			enabled: true, // opt-in by default
		},
		{
			cfg: &TelemeterClientConfig{
				ClusterID: "test",
				Token:     "test",
				Enabled:   &truev,
			},
			enabled: true,
		},
		{
			cfg: &TelemeterClientConfig{
				ClusterID: "test",
				Token:     "test",
				Enabled:   &falsev, // explicitely opt-out
			},
			enabled: false,
		},
	}

	for i, tc := range tcs {
		if got := tc.cfg.IsEnabled(); got != tc.enabled {
			t.Errorf("testcase %d: expected enabled %t, got %t", i, tc.enabled, got)
		}
	}
}

func TestEtcdDefaultsToDisabled(t *testing.T) {
	c, err := NewConfigFromString("")
	if err != nil {
		t.Fatal(err)
	}
	if c.ClusterMonitoringConfiguration.EtcdConfig.IsEnabled() {
		t.Error("an empty configuration should have etcd disabled")
	}
	c, err = NewConfigFromString(`{"etcd":{}}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.ClusterMonitoringConfiguration.EtcdConfig.IsEnabled() {
		t.Error("an empty etcd configuration should have etcd disabled")
	}
}

func TestPromAdapterDedicatedSMsDefaultsToDisabled(t *testing.T) {
	c, err := NewConfigFromString("")
	if err != nil {
		t.Fatal(err)
	}
	if c.ClusterMonitoringConfiguration.K8sPrometheusAdapter.DedicatedServiceMonitors.Enabled {
		t.Error("an empty configuration should have prometheus-adapter dedicated ServiceMonitors dislabled")
	}
	c, err = NewConfigFromString(`{"k8sPrometheusAdapter":{}}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.ClusterMonitoringConfiguration.K8sPrometheusAdapter.DedicatedServiceMonitors.Enabled {
		t.Error("an empty k8sPrometheusAdapter configuration should have prometheus-adapter dedicated ServiceMonitors dislabled")
	}
	c, err = NewConfigFromString(`{"k8sPrometheusAdapter":{"dedicatedServiceMonitors":{}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.ClusterMonitoringConfiguration.K8sPrometheusAdapter.DedicatedServiceMonitors.Enabled {
		t.Error("an empty dedicatedSericeMonitors configuration should have prometheus-adapter dedicated ServiceMonitors dislabled")
	}
}

func TestHttpProxyConfig(t *testing.T) {
	conf := `http:
  httpProxy: http://test.com
  httpsProxy: https://test.com
  noProxy: https://example.com	
`

	c, err := NewConfig(bytes.NewBufferString(conf))
	if err != nil {
		t.Errorf("expected no error parsing config - %v", err)
	}

	tests := []struct {
		name   string
		got    func() string
		expect string
	}{
		{
			name: "expect http proxy value is set",
			got: func() string {
				return c.HTTPProxy()
			},
			expect: "http://test.com",
		},
		{
			name: "expect https proxy value is set",
			got: func() string {
				return c.HTTPSProxy()
			},
			expect: "https://test.com",
		},
		{
			name: "expect http proxy value is set",
			got: func() string {
				return c.NoProxy()
			},
			expect: "https://example.com",
		},
	}

	for i, test := range tests {
		if test.got() != test.expect {
			t.Errorf("testcase %d: expected enabled %s, got %s", i, test.expect, test.got())
		}
	}
}

func TestGrafanaDefaultsToEnabled(t *testing.T) {
	for _, tt := range []struct {
		name          string
		config        string
		expectEnabled bool
	}{
		{
			name:          "empty config",
			config:        "",
			expectEnabled: true,
		},
		{
			name:          "empty grafana config",
			config:        `{"grafana":{}}`,
			expectEnabled: true,
		},
		{
			name:          "grafana explicitly enabled",
			config:        `{"grafana":{"enabled": true}}`,
			expectEnabled: true,
		},
		{
			name:          "grafana disabled",
			config:        `{"grafana":{"enabled": false}}`,
			expectEnabled: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewConfigFromString(tt.config)
			if err != nil {
				t.Fatal(err)
			}

			enabled := c.ClusterMonitoringConfiguration.GrafanaConfig.IsEnabled()

			if enabled != tt.expectEnabled {
				t.Fatalf("GrafanaConfig.IsEnabled() returned %t, expected %t",
					enabled, tt.expectEnabled)
			}
		})
	}
}
