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
	"context"
	"errors"
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

type fakePodCapacity struct {
	capacity int
	err      error
}

func (fpc *fakePodCapacity) PodCapacity(context.Context) (int, error) {
	return fpc.capacity, fpc.err
}

func TestLoadEnforcedBodySizeLimit(t *testing.T) {

	mc_10 := fakePodCapacity{capacity: 10, err: nil}
	mc_1000 := fakePodCapacity{capacity: 1000, err: nil}
	mc_err := fakePodCapacity{capacity: 1000, err: errors.New("error")}
	for _, tt := range []struct {
		name                string
		config              string
		expectBodySizeLimit string
		expectError         bool
		pcr                 PodCapacityReader
	}{
		{
			name:                "empty config",
			config:              "",
			expectBodySizeLimit: "",
			expectError:         false,
			pcr:                 &mc_10,
		},
		{
			name:                "disable body size limit",
			config:              `{"prometheusK8s": {"enforcedBodySizeLimit": "0"}}`,
			expectBodySizeLimit: "0",
			expectError:         false,
			pcr:                 &mc_10,
		},
		{
			name:                "normal size format",
			config:              `{"prometheusK8s": {"enforcedBodySizeLimit": "10KB"}}`,
			expectBodySizeLimit: "10KB",
			expectError:         false,
			pcr:                 &mc_10,
		},
		{
			name:                "invalid size format",
			config:              `{"prometheusK8s": {"enforcedBodySizeLimit": "10EUR"}}`,
			expectBodySizeLimit: "",
			expectError:         true,
			pcr:                 &mc_10,
		},
		{
			name:                "automatic deduced limit: error when getting pods capacity",
			config:              `{"prometheusK8s": {"enforcedBodySizeLimit": "automatic"}}`,
			expectBodySizeLimit: "",
			expectError:         true,
			pcr:                 &mc_err,
		},
		{
			name:                "automatically deduced limit: minimal 48MB",
			config:              `{"prometheusK8s": {"enforcedBodySizeLimit": "automatic"}}`,
			expectBodySizeLimit: "48MB",
			expectError:         false,
			pcr:                 &mc_10,
		},
		{
			name:                "automatically deduced limit: larger than minimal 16MB",
			config:              `{"prometheusK8s": {"enforcedBodySizeLimit": "automatic"}}`,
			expectBodySizeLimit: "77MB",
			expectError:         false,
			pcr:                 &mc_1000,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewConfigFromString(tt.config)
			if err != nil {
				t.Fatalf("config parsing error")
			}

			err = c.LoadEnforcedBodySizeLimit(tt.pcr, context.Background())
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got error %v", err)
			}

			if c.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit != tt.expectBodySizeLimit {
				t.Fatalf("incorrect EnforcedBodySizeLimit is set: got %s, expected %s",
					c.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit,
					tt.expectBodySizeLimit)
			}
		})
	}
}
