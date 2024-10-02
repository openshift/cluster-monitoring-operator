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
	"context"
	"errors"
	"os"
	"testing"

	"github.com/openshift/cluster-monitoring-operator/pkg/metrics"
	prom_testutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestNewConfigFromString(t *testing.T) {
	tcs := []struct {
		name         string
		configString func() string
		shouldFail   bool
		configCheck  func(*Config)
	}{
		{
			name: "yaml from file",
			configString: func() string {
				data, err := os.ReadFile("testdata/cluster-monitoring-config.yaml")
				require.NoError(t, err)
				return string(data)
			},
			configCheck: func(c *Config) {
				require.NotNil(t, c.ClusterMonitoringConfiguration.AlertmanagerMainConfig.VolumeClaimTemplate)
			},
		},
		{
			name: "json string",
			configString: func() string {
				return `{"prometheusK8s": {}}`
			},
		},
		{
			name: "json string with unknown root field",
			configString: func() string {
				return `{"prometheusK8ss": {}}`
			},
			shouldFail: true,
		},
		{
			name: "json string with unknown field",
			configString: func() string {
				return `{"prometheusK8s": {"unknown": "bar"}}`
			},
			shouldFail: true,
		},
		{
			name: "json string with duplicated field",
			// users should be aware of this as unmarshalling would only take one part into account.
			configString: func() string {
				return `{"prometheusK8s": {"foo": {}}, "prometheusK8s": {"bar": {}}}`
			},
			shouldFail: true,
		},
		{
			name: "empty json string",
			configString: func() string {
				return `{}`
			},
		},
		{
			name: "yaml string",
			configString: func() string {
				return `metricsServer:`
			},
		},
		{
			name: "yaml string with unknown root field",
			configString: func() string {
				return `metricsServe:`
			},
			shouldFail: true,
		},
		{
			name: "yaml string with unknown field",
			configString: func() string {
				return `
metricsServer:
  unknown:`
			},
			shouldFail: true,
		},
		{
			name: "yaml string with duplicated field",
			configString: func() string {
				return `
metricsServer:
  foo:
metricsServer:
  bar:`
			},
			shouldFail: true,
		},
		{
			name: "empty yaml string",
			configString: func() string {
				return ``
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewConfigFromString(tc.configString(), false)
			if tc.shouldFail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.configCheck != nil {
				tc.configCheck(c)
			}
		})
	}
}

func TestNewUserConfigFromString(t *testing.T) {
	tcs := []struct {
		name         string
		configString func() string
		shouldFail   bool
		configCheck  func(*UserWorkloadConfiguration)
	}{
		{
			name: "yaml from file",
			configString: func() string {
				data, err := os.ReadFile("testdata/user-workload-monitoring-config.yaml")
				require.NoError(t, err)
				return string(data)
			},
			configCheck: func(uwmc *UserWorkloadConfiguration) {
				require.NotNil(t, uwmc.Prometheus.Retention)
				require.NotNil(t, uwmc.ThanosRuler.Resources)
			},
		},
		{
			name: "json string",
			configString: func() string {
				return `{"thanosRuler": {}}`
			},
		},
		{
			name: "json string with unknown root field",
			configString: func() string {
				return `{"unknown": {}}`
			},
			shouldFail: true,
		},
		{
			name: "json string with unknown field",
			configString: func() string {
				return `{"prometheusOperator": {"unknown": "bar"}}`
			},
			shouldFail: true,
		},
		{
			name: "json string with duplicated field",
			// users should be aware of this as unmarshalling would only take one part into account.
			configString: func() string {
				return `{"prometheus": {"foo": {}}, "prometheus": {"bar": {}}}`
			},
			shouldFail: true,
		},
		{
			name: "empty json string",
			configString: func() string {
				return `{}`
			},
		},
		{
			name: "yaml string",
			configString: func() string {
				return `thanosRuler:`
			},
		},
		{
			name: "yaml string with unknown root field",
			configString: func() string {
				return `unknown:`
			},
			shouldFail: true,
		},
		{
			name: "yaml string with unknown field",
			configString: func() string {
				return `
prometheusOperator:
  unknown:`
			},
			shouldFail: true,
		},
		{
			name: "yaml string with duplicated field",
			configString: func() string {
				return `
thanosRuler:
  foo:
thanosRuler:
  bar:`
			},
			shouldFail: true,
		},
		{
			name: "empty yaml string",
			configString: func() string {
				return ``
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewUserConfigFromString(tc.configString())
			if tc.shouldFail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.configCheck != nil {
				tc.configCheck(c)
			}
		})
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

func TestHttpProxyConfig(t *testing.T) {
	conf := `http:
  httpProxy: http://test.com
  httpsProxy: https://test.com
  noProxy: https://example.com
`

	c, err := NewConfigFromString(conf, false)
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
			c, err := NewConfigFromString(tt.config, false)
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

func TestCollectionProfilePreCheck(t *testing.T) {
	for _, tc := range []struct {
		name          string
		config        string
		expected      CollectionProfile
		expectedError bool
	}{
		{
			name:          "default",
			config:        "",
			expected:      CollectionProfile("full"),
			expectedError: false,
		},
		{
			name: "full_profile",
			config: `prometheusk8s:
  collectionProfile: full
  `,
			expected:      CollectionProfile("full"),
			expectedError: false,
		},
		{
			name: "minimal_profile",
			config: `prometheusk8s:
  collectionProfile: minimal
  `,
			expected:      CollectionProfile("minimal"),
			expectedError: false,
		},
		{
			name: "incorrect_profile",
			config: `prometheusk8s:
  collectionProfile: foo
  `,
			expected:      "",
			expectedError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewConfigFromString(tc.config, true)
			require.NoError(t, err)
			err = c.Precheck()
			if err != nil && tc.expectedError {
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, c.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile)
		})
	}
}

func TestDeprecatedConfig(t *testing.T) {
	for _, tc := range []struct {
		name                string
		config              string
		expectedMetricValue float64
	}{
		{
			name: "setting a field in k8sPrometheusAdapter",
			config: `k8sPrometheusAdapter:
  resources:
    requests:
      cpu: 1m
      memory: 20Mi
  `,
			expectedMetricValue: 1,
		},
		{
			name: "k8sPrometheusAdapter nil",
			config: `k8sPrometheusAdapter:
  `,
			expectedMetricValue: 0,
		},
		{
			name:                "no config set",
			config:              "",
			expectedMetricValue: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewConfigFromString(tc.config, true)
			require.NoError(t, err)
			err = c.Precheck()
			require.NoError(t, err)
			require.Equal(t, tc.expectedMetricValue, prom_testutil.ToFloat64(metrics.DeprecatedConfig))
		})
	}
}
