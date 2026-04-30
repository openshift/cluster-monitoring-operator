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
