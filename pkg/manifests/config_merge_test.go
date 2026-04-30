// Copyright 2018 The Cluster Monitoring Operator Authors.
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
	"testing"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestConfig_MergeClusterMonitoringCRD(t *testing.T) {
	for _, tc := range []struct {
		name     string
		c        string
		cm       *configv1alpha1.ClusterMonitoring
		expected bool
	}{
		{
			name: "cm with invalid UserDefined Mode defaults to false",
			c:    "{}",
			cm: &configv1alpha1.ClusterMonitoring{
				Spec: configv1alpha1.ClusterMonitoringSpec{
					UserDefined: configv1alpha1.UserDefinedMonitoring{Mode: "FooBar"},
				},
			},
			expected: false,
		},
		{
			name: "UserDefinedDisabled sets UserWorkloadEnabled to false",
			c:    "{}",
			cm: &configv1alpha1.ClusterMonitoring{
				Spec: configv1alpha1.ClusterMonitoringSpec{
					UserDefined: configv1alpha1.UserDefinedMonitoring{Mode: configv1alpha1.UserDefinedDisabled},
				},
			},
			expected: false,
		},
		{
			name: "UserDefinedNamespaceIsolated sets UserWorkloadEnabled to true",
			c:    "{}",
			cm: &configv1alpha1.ClusterMonitoring{
				Spec: configv1alpha1.ClusterMonitoringSpec{
					UserDefined: configv1alpha1.UserDefinedMonitoring{Mode: configv1alpha1.UserDefinedNamespaceIsolated},
				},
			},
			expected: true,
		},
		{
			name: "ConfigMap UserWorkloadEnabled wins over CRD",
			c:    "{enableUserWorkload: true}",
			cm: &configv1alpha1.ClusterMonitoring{
				Spec: configv1alpha1.ClusterMonitoringSpec{
					UserDefined: configv1alpha1.UserDefinedMonitoring{Mode: configv1alpha1.UserDefinedDisabled},
				},
			},
			expected: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewConfigFromStringAndClusterMonitoringResource(tc.c, tc.cm)
			require.NoError(t, err)
			require.NotNil(t, c.ClusterMonitoringConfiguration)
			require.NotNil(t, c.ClusterMonitoringConfiguration.UserWorkloadEnabled)
			require.Equal(t, tc.expected, *c.ClusterMonitoringConfiguration.UserWorkloadEnabled)
		})
	}
}

func TestClusterMonitoringMetricsServerSpecEmpty(t *testing.T) {
	require.True(t, clusterMonitoringMetricsServerSpecEmpty(configv1alpha1.MetricsServerConfig{}))
	require.False(t, clusterMonitoringMetricsServerSpecEmpty(configv1alpha1.MetricsServerConfig{
		Verbosity: configv1alpha1.VerbosityLevelInfo,
	}))
	require.False(t, clusterMonitoringMetricsServerSpecEmpty(configv1alpha1.MetricsServerConfig{
		Audit: configv1alpha1.Audit{Profile: configv1alpha1.AuditProfileMetadata},
	}))
}

func TestClusterMonitoringPrometheusOperatorSpecEmpty(t *testing.T) {
	require.True(t, clusterMonitoringPrometheusOperatorSpecEmpty(configv1alpha1.PrometheusOperatorConfig{}))
	require.False(t, clusterMonitoringPrometheusOperatorSpecEmpty(configv1alpha1.PrometheusOperatorConfig{
		LogLevel: configv1alpha1.LogLevelInfo,
	}))
	require.False(t, clusterMonitoringPrometheusOperatorSpecEmpty(configv1alpha1.PrometheusOperatorConfig{
		NodeSelector: map[string]string{"k": "v"},
	}))
}

func TestClusterMonitoringAlertmanagerSpecEmpty(t *testing.T) {
	require.True(t, clusterMonitoringAlertmanagerSpecEmpty(configv1alpha1.AlertmanagerConfig{}))
	require.False(t, clusterMonitoringAlertmanagerSpecEmpty(configv1alpha1.AlertmanagerConfig{
		DeploymentMode: configv1alpha1.AlertManagerDeployModeDefaultConfig,
	}))
}

func TestClusterMonitoringMonitoringPluginSpecEmpty(t *testing.T) {
	require.True(t, clusterMonitoringMonitoringPluginSpecEmpty(configv1alpha1.MonitoringPluginConfig{}))
	require.False(t, clusterMonitoringMonitoringPluginSpecEmpty(configv1alpha1.MonitoringPluginConfig{
		NodeSelector: map[string]string{"k": "v"},
	}))
	require.False(t, clusterMonitoringMonitoringPluginSpecEmpty(configv1alpha1.MonitoringPluginConfig{
		Resources: []configv1alpha1.ContainerResource{{Name: "cpu"}},
	}))
}

func TestLogLevelCRDToManifest(t *testing.T) {
	require.Equal(t, "debug", logLevelCRDToManifest(configv1alpha1.LogLevelDebug))
	require.Equal(t, "", logLevelCRDToManifest(configv1alpha1.LogLevel("Unknown")))
}

func TestConfig_MergeClusterMonitoringCRD_MetricsServerConfigPhase1(t *testing.T) {
	t.Run("CR applies when ConfigMap left MetricsServerConfig nil", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				MetricsServerConfig: configv1alpha1.MetricsServerConfig{
					Verbosity: configv1alpha1.VerbosityLevelInfo,
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.MetricsServerConfig)
		require.Equal(t, uint8(2), c.ClusterMonitoringConfiguration.MetricsServerConfig.Verbosity)
	})
	t.Run("CR ignored when ConfigMap already set MetricsServerConfig", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				MetricsServerConfig: configv1alpha1.MetricsServerConfig{
					Verbosity: configv1alpha1.VerbosityLevelInfo,
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{metricsServer: {verbosity: 1}}", cm)
		require.NoError(t, err)
		require.Equal(t, uint8(1), c.ClusterMonitoringConfiguration.MetricsServerConfig.Verbosity)
	})
}

func TestConfig_MergeClusterMonitoringCRD_PrometheusOperatorConfigPhase1(t *testing.T) {
	t.Run("CR applies when ConfigMap left PrometheusOperatorConfig nil", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				PrometheusOperatorConfig: configv1alpha1.PrometheusOperatorConfig{
					LogLevel: configv1alpha1.LogLevelDebug,
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.PrometheusOperatorConfig)
		require.Equal(t, "debug", c.ClusterMonitoringConfiguration.PrometheusOperatorConfig.LogLevel)
	})
	t.Run("CR ignored when ConfigMap already set PrometheusOperatorConfig", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				PrometheusOperatorConfig: configv1alpha1.PrometheusOperatorConfig{
					LogLevel: configv1alpha1.LogLevelDebug,
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{prometheusOperator: {logLevel: info}}", cm)
		require.NoError(t, err)
		require.Equal(t, "info", c.ClusterMonitoringConfiguration.PrometheusOperatorConfig.LogLevel)
	})
	t.Run("CR maps ContainerResource to Resources", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				PrometheusOperatorConfig: configv1alpha1.PrometheusOperatorConfig{
					Resources: []configv1alpha1.ContainerResource{
						{
							Name:    "cpu",
							Request: resource.MustParse("100m"),
							Limit:   resource.MustParse("200m"),
						},
					},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.PrometheusOperatorConfig.Resources)
		require.Equal(t, resource.MustParse("100m"), c.ClusterMonitoringConfiguration.PrometheusOperatorConfig.Resources.Requests[v1.ResourceCPU])
		require.Equal(t, resource.MustParse("200m"), c.ClusterMonitoringConfiguration.PrometheusOperatorConfig.Resources.Limits[v1.ResourceCPU])
	})
}

func TestConfig_MergeClusterMonitoringCRD_AlertmanagerMainConfigPhase1(t *testing.T) {
	t.Run("CR applies when ConfigMap left AlertmanagerMainConfig nil", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				AlertmanagerConfig: configv1alpha1.AlertmanagerConfig{
					DeploymentMode: configv1alpha1.AlertManagerDeployModeCustomConfig,
					CustomConfig: configv1alpha1.AlertmanagerCustomConfig{
						LogLevel: configv1alpha1.LogLevelDebug,
					},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.AlertmanagerMainConfig)
		require.Equal(t, "debug", c.ClusterMonitoringConfiguration.AlertmanagerMainConfig.LogLevel)
	})
	t.Run("CR ignored when ConfigMap already set AlertmanagerMainConfig", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				AlertmanagerConfig: configv1alpha1.AlertmanagerConfig{
					DeploymentMode: configv1alpha1.AlertManagerDeployModeCustomConfig,
					CustomConfig: configv1alpha1.AlertmanagerCustomConfig{
						LogLevel: configv1alpha1.LogLevelDebug,
					},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{alertmanagerMain: {logLevel: info}}", cm)
		require.NoError(t, err)
		require.Equal(t, "info", c.ClusterMonitoringConfiguration.AlertmanagerMainConfig.LogLevel)
	})
	t.Run("CR Disabled sets enabled false", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				AlertmanagerConfig: configv1alpha1.AlertmanagerConfig{
					DeploymentMode: configv1alpha1.AlertManagerDeployModeDisabled,
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Enabled)
		require.False(t, *c.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Enabled)
	})
}

func TestConfig_MergeClusterMonitoringCRD_MonitoringPluginConfigPhase1(t *testing.T) {
	t.Run("CR applies when ConfigMap left MonitoringPluginConfig nil", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				MonitoringPluginConfig: configv1alpha1.MonitoringPluginConfig{
					NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.MonitoringPluginConfig)
		require.Equal(t, "linux", c.ClusterMonitoringConfiguration.MonitoringPluginConfig.NodeSelector["kubernetes.io/os"])
	})
	t.Run("CR ignored when ConfigMap already set MonitoringPluginConfig", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				MonitoringPluginConfig: configv1alpha1.MonitoringPluginConfig{
					NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{monitoringPlugin: {nodeSelector: {test: from-cm}}}", cm)
		require.NoError(t, err)
		require.Equal(t, "from-cm", c.ClusterMonitoringConfiguration.MonitoringPluginConfig.NodeSelector["test"])
	})
	t.Run("CR maps ContainerResource to Resources", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				MonitoringPluginConfig: configv1alpha1.MonitoringPluginConfig{
					Resources: []configv1alpha1.ContainerResource{
						{
							Name:    "cpu",
							Request: resource.MustParse("100m"),
							Limit:   resource.MustParse("200m"),
						},
					},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.MonitoringPluginConfig.Resources)
		require.Equal(t, resource.MustParse("100m"), c.ClusterMonitoringConfiguration.MonitoringPluginConfig.Resources.Requests[v1.ResourceCPU])
		require.Equal(t, resource.MustParse("200m"), c.ClusterMonitoringConfiguration.MonitoringPluginConfig.Resources.Limits[v1.ResourceCPU])
	})
}
