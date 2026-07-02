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
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
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
	require.False(t, clusterMonitoringMetricsServerSpecEmpty(configv1alpha1.MetricsServerConfig{
		Resources: []configv1alpha1.ContainerResource{
			{Name: "cpu", Request: resource.MustParse("10m")},
		},
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
		Resources: []configv1alpha1.ContainerResource{
			{Name: "cpu", Request: resource.MustParse("10m")},
		},
	}))
}

func TestClusterMonitoringPrometheusOperatorAdmissionWebhookSpecEmpty(t *testing.T) {
	require.True(t, clusterMonitoringPrometheusOperatorAdmissionWebhookSpecEmpty(configv1alpha1.PrometheusOperatorAdmissionWebhookConfig{}))
	require.False(t, clusterMonitoringPrometheusOperatorAdmissionWebhookSpecEmpty(configv1alpha1.PrometheusOperatorAdmissionWebhookConfig{
		Resources: []configv1alpha1.ContainerResource{
			{Name: "cpu", Request: resource.MustParse("10m")},
		},
	}))
	require.False(t, clusterMonitoringPrometheusOperatorAdmissionWebhookSpecEmpty(configv1alpha1.PrometheusOperatorAdmissionWebhookConfig{
		TopologySpreadConstraints: []v1.TopologySpreadConstraint{
			{MaxSkew: 1, TopologyKey: "kubernetes.io/hostname"},
		},
	}))
}

func TestClusterMonitoringNodeExporterCollectorsEmpty(t *testing.T) {
	require.True(t, clusterMonitoringNodeExporterCollectorsEmpty(configv1alpha1.NodeExporterCollectorConfig{}))
	require.False(t, clusterMonitoringNodeExporterCollectorsEmpty(configv1alpha1.NodeExporterCollectorConfig{
		Softirqs: configv1alpha1.NodeExporterCollectorSoftirqsConfig{
			CollectionPolicy: configv1alpha1.NodeExporterCollectorCollectionPolicyCollect,
		},
	}))
	require.False(t, clusterMonitoringNodeExporterCollectorsEmpty(configv1alpha1.NodeExporterCollectorConfig{
		CpuFreq: configv1alpha1.NodeExporterCollectorCpufreqConfig{
			CollectionPolicy: configv1alpha1.NodeExporterCollectorCollectionPolicyDoNotCollect,
		},
	}))
}

func TestClusterMonitoringTelemeterClientSpecEmpty(t *testing.T) {
	require.True(t, clusterMonitoringTelemeterClientSpecEmpty(configv1alpha1.TelemeterClientConfig{}))
	require.False(t, clusterMonitoringTelemeterClientSpecEmpty(configv1alpha1.TelemeterClientConfig{
		NodeSelector: map[string]string{"k": "v"},
	}))
	require.False(t, clusterMonitoringTelemeterClientSpecEmpty(configv1alpha1.TelemeterClientConfig{
		Resources: []configv1alpha1.ContainerResource{
			{Name: "cpu", Request: resource.MustParse("10m")},
		},
	}))
	require.False(t, clusterMonitoringTelemeterClientSpecEmpty(configv1alpha1.TelemeterClientConfig{
		Tolerations: []v1.Toleration{
			{Key: "key", Operator: v1.TolerationOpEqual, Value: "val"},
		},
	}))
}

func TestClusterMonitoringThanosQuerierSpecEmpty(t *testing.T) {
	require.True(t, clusterMonitoringThanosQuerierSpecEmpty(configv1alpha1.ThanosQuerierConfig{}))
	require.False(t, clusterMonitoringThanosQuerierSpecEmpty(configv1alpha1.ThanosQuerierConfig{
		NodeSelector: map[string]string{"k": "v"},
	}))
	require.False(t, clusterMonitoringThanosQuerierSpecEmpty(configv1alpha1.ThanosQuerierConfig{
		Resources: []configv1alpha1.ContainerResource{
			{Name: "cpu", Request: resource.MustParse("10m")},
		},
	}))
	require.False(t, clusterMonitoringThanosQuerierSpecEmpty(configv1alpha1.ThanosQuerierConfig{
		Tolerations: []v1.Toleration{
			{Key: "key", Operator: v1.TolerationOpEqual, Value: "val"},
		},
	}))
}

func TestClusterMonitoringNodeExporterSpecEmpty(t *testing.T) {
	require.True(t, clusterMonitoringNodeExporterSpecEmpty(configv1alpha1.NodeExporterConfig{}))
	require.False(t, clusterMonitoringNodeExporterSpecEmpty(configv1alpha1.NodeExporterConfig{
		MaxProcs: 2,
	}))
	require.False(t, clusterMonitoringNodeExporterSpecEmpty(configv1alpha1.NodeExporterConfig{
		Collectors: configv1alpha1.NodeExporterCollectorConfig{
			Softirqs: configv1alpha1.NodeExporterCollectorSoftirqsConfig{
				CollectionPolicy: configv1alpha1.NodeExporterCollectorCollectionPolicyCollect,
			},
		},
	}))
}

func TestClusterMonitoringPrometheusSpecEmpty(t *testing.T) {
	require.True(t, clusterMonitoringPrometheusSpecEmpty(configv1alpha1.PrometheusConfig{}))
	require.False(t, clusterMonitoringPrometheusSpecEmpty(configv1alpha1.PrometheusConfig{
		LogLevel: configv1alpha1.LogLevelInfo,
	}))
	require.False(t, clusterMonitoringPrometheusSpecEmpty(configv1alpha1.PrometheusConfig{
		NodeSelector: map[string]string{"k": "v"},
	}))
	require.False(t, clusterMonitoringPrometheusSpecEmpty(configv1alpha1.PrometheusConfig{
		Retention: configv1alpha1.Retention{Duration: "30d"},
	}))
	require.False(t, clusterMonitoringPrometheusSpecEmpty(configv1alpha1.PrometheusConfig{
		CollectionProfile: configv1alpha1.CollectionProfileMinimal,
	}))
}

func TestLogLevelCRDToManifest(t *testing.T) {
	ll, err := logLevelCRDToManifest(configv1alpha1.LogLevelDebug)
	require.NoError(t, err)
	require.Equal(t, "debug", ll)

	ll, err = logLevelCRDToManifest("")
	require.NoError(t, err)
	require.Equal(t, "", ll)

	_, err = logLevelCRDToManifest(configv1alpha1.LogLevel("Unknown"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported log level")
}

func TestCollectionProfileCRDToManifest(t *testing.T) {
	cp, err := collectionProfileCRDToManifest(configv1alpha1.CollectionProfileMinimal)
	require.NoError(t, err)
	require.Equal(t, CollectionProfile(MinimalCollectionProfile), cp)

	cp, err = collectionProfileCRDToManifest("")
	require.NoError(t, err)
	require.Equal(t, CollectionProfile(""), cp)

	_, err = collectionProfileCRDToManifest(configv1alpha1.CollectionProfile("Invalid"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported collection profile")
}

func TestVerbosityLevelToNumeric(t *testing.T) {
	v, err := verbosityLevelToNumeric(configv1alpha1.VerbosityLevelInfo)
	require.NoError(t, err)
	require.Equal(t, uint8(2), v)

	_, err = verbosityLevelToNumeric(configv1alpha1.VerbosityLevel("Invalid"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported verbosity level")
}

func TestAuditProfileCRDToManifest(t *testing.T) {
	p, err := auditProfileCRDToManifest(configv1alpha1.AuditProfileMetadata)
	require.NoError(t, err)
	require.Equal(t, auditv1.LevelMetadata, p)

	_, err = auditProfileCRDToManifest(configv1alpha1.AuditProfile("Invalid"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported audit profile")
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
	t.Run("CR maps ContainerResource to Resources", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				MetricsServerConfig: configv1alpha1.MetricsServerConfig{
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
		require.NotNil(t, c.ClusterMonitoringConfiguration.MetricsServerConfig.Resources)
		require.Equal(t, resource.MustParse("100m"), c.ClusterMonitoringConfiguration.MetricsServerConfig.Resources.Requests[v1.ResourceCPU])
		require.Equal(t, resource.MustParse("200m"), c.ClusterMonitoringConfiguration.MetricsServerConfig.Resources.Limits[v1.ResourceCPU])
	})
	t.Run("CR returns error for unsupported verbosity", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				MetricsServerConfig: configv1alpha1.MetricsServerConfig{
					Verbosity: configv1alpha1.VerbosityLevel("Invalid"),
				},
			},
		}
		_, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported verbosity level")
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

func TestConfig_MergeClusterMonitoringCRD_MonitoringPluginConfigPhase1(t *testing.T) {
	t.Run("CR applies when ConfigMap left MonitoringPluginConfig nil", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				MonitoringPluginConfig: configv1alpha1.MonitoringPluginConfig{
					NodeSelector: map[string]string{"role": "monitoring"},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.MonitoringPluginConfig)
		require.Equal(t, map[string]string{"role": "monitoring"}, c.ClusterMonitoringConfiguration.MonitoringPluginConfig.NodeSelector)
	})
	t.Run("CR ignored when ConfigMap already set MonitoringPluginConfig", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				MonitoringPluginConfig: configv1alpha1.MonitoringPluginConfig{
					NodeSelector: map[string]string{"from": "crd"},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{monitoringPlugin: {nodeSelector: {from: configmap}}}", cm)
		require.NoError(t, err)
		require.Equal(t, map[string]string{"from": "configmap"}, c.ClusterMonitoringConfiguration.MonitoringPluginConfig.NodeSelector)
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

func TestConfig_MergeClusterMonitoringCRD_PrometheusOperatorAdmissionWebhookConfigPhase1(t *testing.T) {
	t.Run("CR applies when ConfigMap left PrometheusOperatorAdmissionWebhookConfig nil", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				PrometheusOperatorAdmissionWebhookConfig: configv1alpha1.PrometheusOperatorAdmissionWebhookConfig{
					Resources: []configv1alpha1.ContainerResource{
						{Name: "cpu", Request: resource.MustParse("10m")},
					},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig)
		require.NotNil(t, c.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig.Resources)
		require.Equal(t, resource.MustParse("10m"), c.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig.Resources.Requests[v1.ResourceCPU])
	})
	t.Run("CR ignored when ConfigMap already set PrometheusOperatorAdmissionWebhookConfig", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				PrometheusOperatorAdmissionWebhookConfig: configv1alpha1.PrometheusOperatorAdmissionWebhookConfig{
					Resources: []configv1alpha1.ContainerResource{
						{Name: "cpu", Request: resource.MustParse("999m")},
					},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{prometheusOperatorAdmissionWebhook: {resources: {requests: {cpu: 5m}}}}", cm)
		require.NoError(t, err)
		require.Equal(t, resource.MustParse("5m"), c.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig.Resources.Requests[v1.ResourceCPU])
	})
	t.Run("CR maps ContainerResource to Resources", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				PrometheusOperatorAdmissionWebhookConfig: configv1alpha1.PrometheusOperatorAdmissionWebhookConfig{
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
		require.NotNil(t, c.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig.Resources)
		require.Equal(t, resource.MustParse("100m"), c.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig.Resources.Requests[v1.ResourceCPU])
		require.Equal(t, resource.MustParse("200m"), c.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig.Resources.Limits[v1.ResourceCPU])
	})
}

func TestConfig_MergeClusterMonitoringCRD_TelemeterClientConfigPhase1(t *testing.T) {
	t.Run("CR applies when ConfigMap left TelemeterClientConfig nil", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				TelemeterClientConfig: configv1alpha1.TelemeterClientConfig{
					NodeSelector: map[string]string{"role": "infra"},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.TelemeterClientConfig)
		require.Equal(t, map[string]string{"role": "infra"}, c.ClusterMonitoringConfiguration.TelemeterClientConfig.NodeSelector)
	})
	t.Run("CR ignored when ConfigMap already set TelemeterClientConfig", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				TelemeterClientConfig: configv1alpha1.TelemeterClientConfig{
					NodeSelector: map[string]string{"from": "crd"},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{telemeterClient: {nodeSelector: {from: configmap}}}", cm)
		require.NoError(t, err)
		require.Equal(t, map[string]string{"from": "configmap"}, c.ClusterMonitoringConfiguration.TelemeterClientConfig.NodeSelector)
	})
	t.Run("CR maps ContainerResource to Resources", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				TelemeterClientConfig: configv1alpha1.TelemeterClientConfig{
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
		require.NotNil(t, c.ClusterMonitoringConfiguration.TelemeterClientConfig.Resources)
		require.Equal(t, resource.MustParse("100m"), c.ClusterMonitoringConfiguration.TelemeterClientConfig.Resources.Requests[v1.ResourceCPU])
		require.Equal(t, resource.MustParse("200m"), c.ClusterMonitoringConfiguration.TelemeterClientConfig.Resources.Limits[v1.ResourceCPU])
	})
}

func TestConfig_MergeClusterMonitoringCRD_ThanosQuerierConfigPhase1(t *testing.T) {
	t.Run("CR applies when ConfigMap left ThanosQuerierConfig nil", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				ThanosQuerierConfig: configv1alpha1.ThanosQuerierConfig{
					NodeSelector: map[string]string{"role": "infra"},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.ThanosQuerierConfig)
		require.Equal(t, map[string]string{"role": "infra"}, c.ClusterMonitoringConfiguration.ThanosQuerierConfig.NodeSelector)
	})
	t.Run("CR ignored when ConfigMap already set ThanosQuerierConfig", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				ThanosQuerierConfig: configv1alpha1.ThanosQuerierConfig{
					NodeSelector: map[string]string{"from": "crd"},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{thanosQuerier: {nodeSelector: {from: configmap}}}", cm)
		require.NoError(t, err)
		require.Equal(t, map[string]string{"from": "configmap"}, c.ClusterMonitoringConfiguration.ThanosQuerierConfig.NodeSelector)
	})
	t.Run("CR maps ContainerResource to Resources", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				ThanosQuerierConfig: configv1alpha1.ThanosQuerierConfig{
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
		require.NotNil(t, c.ClusterMonitoringConfiguration.ThanosQuerierConfig.Resources)
		require.Equal(t, resource.MustParse("100m"), c.ClusterMonitoringConfiguration.ThanosQuerierConfig.Resources.Requests[v1.ResourceCPU])
		require.Equal(t, resource.MustParse("200m"), c.ClusterMonitoringConfiguration.ThanosQuerierConfig.Resources.Limits[v1.ResourceCPU])
	})
}

func TestConfig_MergeClusterMonitoringCRD_NodeExporterConfigPhase1(t *testing.T) {
	softirqsCR := func(policy configv1alpha1.NodeExporterCollectorCollectionPolicy) *configv1alpha1.ClusterMonitoring {
		return &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				NodeExporterConfig: configv1alpha1.NodeExporterConfig{
					Collectors: configv1alpha1.NodeExporterCollectorConfig{
						Softirqs: configv1alpha1.NodeExporterCollectorSoftirqsConfig{
							CollectionPolicy: policy,
						},
					},
				},
			},
		}
	}
	t.Run("CR applies when ConfigMap omits nodeExporter", func(t *testing.T) {
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", softirqsCR(configv1alpha1.NodeExporterCollectorCollectionPolicyCollect))
		require.NoError(t, err)
		require.True(t, c.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.Softirqs.Enabled)
	})
	t.Run("CR applies when ConfigMap sets nodeExporter to null", func(t *testing.T) {
		c, err := NewConfigFromStringAndClusterMonitoringResource("nodeExporter: null", softirqsCR(configv1alpha1.NodeExporterCollectorCollectionPolicyCollect))
		require.NoError(t, err)
		require.True(t, c.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.Softirqs.Enabled)
	})
	t.Run("CR ignored when ConfigMap declares nodeExporter without softirqs", func(t *testing.T) {
		c, err := NewConfigFromStringAndClusterMonitoringResource(`nodeExporter:
  maxProcs: 2
`, softirqsCR(configv1alpha1.NodeExporterCollectorCollectionPolicyCollect))
		require.NoError(t, err)
		require.Equal(t, uint32(2), c.ClusterMonitoringConfiguration.NodeExporterConfig.MaxProcs)
		require.False(t, c.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.Softirqs.Enabled)
	})
	t.Run("CR ignored when ConfigMap declares collectors.softirqs", func(t *testing.T) {
		c, err := NewConfigFromStringAndClusterMonitoringResource(`nodeExporter:
  collectors:
    softirqs:
      enabled: false
`, softirqsCR(configv1alpha1.NodeExporterCollectorCollectionPolicyCollect))
		require.NoError(t, err)
		require.False(t, c.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.Softirqs.Enabled)
	})
	t.Run("CR maps DoNotCollect to disabled", func(t *testing.T) {
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", softirqsCR(configv1alpha1.NodeExporterCollectorCollectionPolicyDoNotCollect))
		require.NoError(t, err)
		require.False(t, c.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.Softirqs.Enabled)
	})
}

func TestClusterMonitoringOpenShiftStateMetricsSpecEmpty(t *testing.T) {
	require.True(t, clusterMonitoringOpenShiftStateMetricsSpecEmpty(configv1alpha1.OpenShiftStateMetricsConfig{}))
	require.False(t, clusterMonitoringOpenShiftStateMetricsSpecEmpty(configv1alpha1.OpenShiftStateMetricsConfig{
		NodeSelector: map[string]string{"k": "v"},
	}))
	require.False(t, clusterMonitoringOpenShiftStateMetricsSpecEmpty(configv1alpha1.OpenShiftStateMetricsConfig{
		Resources: []configv1alpha1.ContainerResource{
			{Name: "cpu", Request: resource.MustParse("10m")},
		},
	}))
	require.False(t, clusterMonitoringOpenShiftStateMetricsSpecEmpty(configv1alpha1.OpenShiftStateMetricsConfig{
		Tolerations: []v1.Toleration{
			{Key: "key", Operator: v1.TolerationOpEqual, Value: "val"},
		},
	}))
	require.False(t, clusterMonitoringOpenShiftStateMetricsSpecEmpty(configv1alpha1.OpenShiftStateMetricsConfig{
		TopologySpreadConstraints: []v1.TopologySpreadConstraint{
			{MaxSkew: 1, TopologyKey: "kubernetes.io/hostname"},
		},
	}))
}

func TestClusterMonitoringKubeStateMetricsSpecEmpty(t *testing.T) {
	require.True(t, clusterMonitoringKubeStateMetricsSpecEmpty(configv1alpha1.KubeStateMetricsConfig{}))
	require.False(t, clusterMonitoringKubeStateMetricsSpecEmpty(configv1alpha1.KubeStateMetricsConfig{
		NodeSelector: map[string]string{"k": "v"},
	}))
	require.False(t, clusterMonitoringKubeStateMetricsSpecEmpty(configv1alpha1.KubeStateMetricsConfig{
		Resources: []configv1alpha1.ContainerResource{
			{Name: "cpu", Request: resource.MustParse("10m")},
		},
	}))
	require.False(t, clusterMonitoringKubeStateMetricsSpecEmpty(configv1alpha1.KubeStateMetricsConfig{
		Tolerations: []v1.Toleration{
			{Key: "key", Operator: v1.TolerationOpEqual, Value: "val"},
		},
	}))
	require.False(t, clusterMonitoringKubeStateMetricsSpecEmpty(configv1alpha1.KubeStateMetricsConfig{
		TopologySpreadConstraints: []v1.TopologySpreadConstraint{
			{MaxSkew: 1, TopologyKey: "kubernetes.io/hostname"},
		},
	}))
	require.False(t, clusterMonitoringKubeStateMetricsSpecEmpty(configv1alpha1.KubeStateMetricsConfig{
		AdditionalResourceLabels: []configv1alpha1.KubeStateMetricsResourceLabels{
			{Resource: configv1alpha1.KubeStateMetricsResourceJob, Labels: []configv1alpha1.KubeStateMetricsLabelName{"app"}},
		},
	}))
}

func TestConfig_MergeClusterMonitoringCRD_OpenShiftStateMetricsConfigPhase1(t *testing.T) {
	t.Run("CR applies when ConfigMap left OpenShiftMetricsConfig nil", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				OpenShiftStateMetricsConfig: configv1alpha1.OpenShiftStateMetricsConfig{
					NodeSelector: map[string]string{"role": "infra"},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.OpenShiftMetricsConfig)
		require.Equal(t, map[string]string{"role": "infra"}, c.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.NodeSelector)
	})
	t.Run("CR ignored when ConfigMap already set OpenShiftMetricsConfig", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				OpenShiftStateMetricsConfig: configv1alpha1.OpenShiftStateMetricsConfig{
					NodeSelector: map[string]string{"from": "crd"},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{openshiftStateMetrics: {nodeSelector: {from: configmap}}}", cm)
		require.NoError(t, err)
		require.Equal(t, map[string]string{"from": "configmap"}, c.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.NodeSelector)
	})
	t.Run("CR maps ContainerResource to Resources", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				OpenShiftStateMetricsConfig: configv1alpha1.OpenShiftStateMetricsConfig{
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
		require.NotNil(t, c.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.Resources)
		require.Equal(t, resource.MustParse("100m"), c.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.Resources.Requests[v1.ResourceCPU])
		require.Equal(t, resource.MustParse("200m"), c.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.Resources.Limits[v1.ResourceCPU])
	})
}

func TestConfig_MergeClusterMonitoringCRD_KubeStateMetricsConfigPhase1(t *testing.T) {
	t.Run("CR applies when ConfigMap left KubeStateMetricsConfig nil", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				KubeStateMetricsConfig: configv1alpha1.KubeStateMetricsConfig{
					NodeSelector: map[string]string{"role": "infra"},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.KubeStateMetricsConfig)
		require.Equal(t, map[string]string{"role": "infra"}, c.ClusterMonitoringConfiguration.KubeStateMetricsConfig.NodeSelector)
	})
	t.Run("CR ignored when ConfigMap already set KubeStateMetricsConfig", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				KubeStateMetricsConfig: configv1alpha1.KubeStateMetricsConfig{
					NodeSelector: map[string]string{"from": "crd"},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{kubeStateMetrics: {nodeSelector: {from: configmap}}}", cm)
		require.NoError(t, err)
		require.Equal(t, map[string]string{"from": "configmap"}, c.ClusterMonitoringConfiguration.KubeStateMetricsConfig.NodeSelector)
	})
	t.Run("CR maps ContainerResource to Resources", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				KubeStateMetricsConfig: configv1alpha1.KubeStateMetricsConfig{
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
		require.NotNil(t, c.ClusterMonitoringConfiguration.KubeStateMetricsConfig.Resources)
		require.Equal(t, resource.MustParse("100m"), c.ClusterMonitoringConfiguration.KubeStateMetricsConfig.Resources.Requests[v1.ResourceCPU])
		require.Equal(t, resource.MustParse("200m"), c.ClusterMonitoringConfiguration.KubeStateMetricsConfig.Resources.Limits[v1.ResourceCPU])
	})
	t.Run("CR maps AdditionalResourceLabels with resource name conversion", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				KubeStateMetricsConfig: configv1alpha1.KubeStateMetricsConfig{
					AdditionalResourceLabels: []configv1alpha1.KubeStateMetricsResourceLabels{
						{
							Resource: configv1alpha1.KubeStateMetricsResourceJob,
							Labels:   []configv1alpha1.KubeStateMetricsLabelName{"app", "team"},
						},
						{
							Resource: configv1alpha1.KubeStateMetricsResourceCronJob,
							Labels:   []configv1alpha1.KubeStateMetricsLabelName{"*"},
						},
					},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.KubeStateMetricsConfig)
		require.Len(t, c.ClusterMonitoringConfiguration.KubeStateMetricsConfig.AdditionalResourceLabels, 2)
		require.Equal(t, "jobs", c.ClusterMonitoringConfiguration.KubeStateMetricsConfig.AdditionalResourceLabels[0].Resource)
		require.Equal(t, []string{"app", "team"}, c.ClusterMonitoringConfiguration.KubeStateMetricsConfig.AdditionalResourceLabels[0].Labels)
		require.Equal(t, "cronjobs", c.ClusterMonitoringConfiguration.KubeStateMetricsConfig.AdditionalResourceLabels[1].Resource)
		require.Equal(t, []string{"*"}, c.ClusterMonitoringConfiguration.KubeStateMetricsConfig.AdditionalResourceLabels[1].Labels)
	})
	t.Run("CR returns error for unknown resource name", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				KubeStateMetricsConfig: configv1alpha1.KubeStateMetricsConfig{
					AdditionalResourceLabels: []configv1alpha1.KubeStateMetricsResourceLabels{
						{
							Resource: "UnknownResource",
							Labels:   []configv1alpha1.KubeStateMetricsLabelName{"foo"},
						},
					},
				},
			},
		}
		_, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown kube-state-metrics resource name")
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
	t.Run("CR returns error for unsupported deployment mode", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				AlertmanagerConfig: configv1alpha1.AlertmanagerConfig{
					DeploymentMode: configv1alpha1.AlertManagerDeployMode("Invalid"),
				},
			},
		}
		_, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported alertmanager deployment mode")
	})
}

func TestConfig_MergeClusterMonitoringCRD_PrometheusK8sConfigPhase1(t *testing.T) {
	t.Run("CR applies when ConfigMap left PrometheusK8sConfig nil", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				PrometheusConfig: configv1alpha1.PrometheusConfig{
					LogLevel:          configv1alpha1.LogLevelDebug,
					CollectionProfile: configv1alpha1.CollectionProfileMinimal,
					Retention:         configv1alpha1.Retention{Duration: "30d"},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.NotNil(t, c.ClusterMonitoringConfiguration.PrometheusK8sConfig)
		require.Equal(t, "debug", c.ClusterMonitoringConfiguration.PrometheusK8sConfig.LogLevel)
		require.Equal(t, CollectionProfile(MinimalCollectionProfile), c.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile)
		require.Equal(t, "30d", c.ClusterMonitoringConfiguration.PrometheusK8sConfig.Retention)
	})
	t.Run("CR ignored when ConfigMap already set PrometheusK8sConfig", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				PrometheusConfig: configv1alpha1.PrometheusConfig{
					LogLevel: configv1alpha1.LogLevelDebug,
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{prometheusK8s: {logLevel: info}}", cm)
		require.NoError(t, err)
		require.Equal(t, "info", c.ClusterMonitoringConfiguration.PrometheusK8sConfig.LogLevel)
	})
	t.Run("CR maps ContainerResource to Resources", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				PrometheusConfig: configv1alpha1.PrometheusConfig{
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
		require.NotNil(t, c.ClusterMonitoringConfiguration.PrometheusK8sConfig.Resources)
		require.Equal(t, resource.MustParse("100m"), c.ClusterMonitoringConfiguration.PrometheusK8sConfig.Resources.Requests[v1.ResourceCPU])
		require.Equal(t, resource.MustParse("200m"), c.ClusterMonitoringConfiguration.PrometheusK8sConfig.Resources.Limits[v1.ResourceCPU])
	})
	t.Run("CR maps external labels and enforced body size limit", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				PrometheusConfig: configv1alpha1.PrometheusConfig{
					EnforcedBodySizeLimitBytes: 4194304,
					ExternalLabels: []configv1alpha1.Label{
						{Key: "region", Value: "us-east"},
					},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.Equal(t, "4194304", c.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit)
		require.Equal(t, ExternalLabels{"region": "us-east"}, c.ClusterMonitoringConfiguration.PrometheusK8sConfig.ExternalLabels)
	})
	t.Run("CR maps Prometheus retention strings through without conversion", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				PrometheusConfig: configv1alpha1.PrometheusConfig{
					Retention: configv1alpha1.Retention{
						Duration: "15h",
						Size:     "500MiB",
					},
				},
			},
		}
		c, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.NoError(t, err)
		require.Equal(t, "15h", c.ClusterMonitoringConfiguration.PrometheusK8sConfig.Retention)
		require.Equal(t, "500MiB", c.ClusterMonitoringConfiguration.PrometheusK8sConfig.RetentionSize)
	})
	t.Run("CR returns error for unsupported collection profile", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				PrometheusConfig: configv1alpha1.PrometheusConfig{
					CollectionProfile: configv1alpha1.CollectionProfile("Invalid"),
				},
			},
		}
		_, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported collection profile")
	})
	t.Run("CR returns error for unsupported log level", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				PrometheusConfig: configv1alpha1.PrometheusConfig{
					LogLevel: configv1alpha1.LogLevel("Unknown"),
				},
			},
		}
		_, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported log level")
	})
	t.Run("CR returns error when authorization credentials are missing", func(t *testing.T) {
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				PrometheusConfig: configv1alpha1.PrometheusConfig{
					RemoteWrite: []configv1alpha1.RemoteWriteSpec{
						{
							URL: "https://example.com/api/v1/write",
							AuthorizationConfig: configv1alpha1.RemoteWriteAuthorization{
								Type: configv1alpha1.RemoteWriteAuthorizationTypeAuthorization,
							},
						},
					},
				},
			},
		}
		_, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
		require.Error(t, err)
		require.Contains(t, err.Error(), "authorization is required")
	})
}
