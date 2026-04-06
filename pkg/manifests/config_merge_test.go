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
	"k8s.io/utils/ptr"
)

func TestApplyUserDefinedMode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		udm      configv1alpha1.UserDefinedMonitoring
		expected *bool
	}{
		{
			name:     "Disabled",
			udm:      configv1alpha1.UserDefinedMonitoring{Mode: configv1alpha1.UserDefinedDisabled},
			expected: ptr.To(false),
		},
		{
			name:     "NamespaceIsolated",
			udm:      configv1alpha1.UserDefinedMonitoring{Mode: configv1alpha1.UserDefinedNamespaceIsolated},
			expected: ptr.To(true),
		},
		{
			name:     "empty mode",
			udm:      configv1alpha1.UserDefinedMonitoring{},
			expected: nil,
		},
		{
			name:     "unknown mode",
			udm:      configv1alpha1.UserDefinedMonitoring{Mode: "Unknown"},
			expected: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := applyUserDefinedMode(tc.udm)
			if tc.expected == nil {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, *tc.expected, *got)
		})
	}
}

func TestConfig_MergeClusterMonitoringCRD(t *testing.T) {
	ptrFalse := ptr.To(false)
	ptrTrue := ptr.To(true)

	for _, tc := range []struct {
		name        string
		c           *Config
		cm          *configv1alpha1.ClusterMonitoring
		expectValue *bool
	}{
		{
			name: "cm nil leaves config unchanged",
			c:    &Config{},
			cm:   nil,
		},
		{
			name: "UserDefinedDisabled sets UserWorkloadEnabled to false",
			c:    &Config{},
			cm: &configv1alpha1.ClusterMonitoring{
				Spec: configv1alpha1.ClusterMonitoringSpec{
					UserDefined: configv1alpha1.UserDefinedMonitoring{Mode: configv1alpha1.UserDefinedDisabled},
				},
			},
			expectValue: ptrFalse,
		},
		{
			name: "UserDefinedNamespaceIsolated sets UserWorkloadEnabled to true",
			c:    &Config{},
			cm: &configv1alpha1.ClusterMonitoring{
				Spec: configv1alpha1.ClusterMonitoringSpec{
					UserDefined: configv1alpha1.UserDefinedMonitoring{Mode: configv1alpha1.UserDefinedNamespaceIsolated},
				},
			},
			expectValue: ptrTrue,
		},
		{
			name: "ConfigMap UserWorkloadEnabled wins over CRD",
			c: &Config{
				ClusterMonitoringConfiguration: &ClusterMonitoringConfiguration{
					UserWorkloadEnabled: ptrTrue,
				},
			},
			cm: &configv1alpha1.ClusterMonitoring{
				Spec: configv1alpha1.ClusterMonitoringSpec{
					UserDefined: configv1alpha1.UserDefinedMonitoring{Mode: configv1alpha1.UserDefinedDisabled},
				},
			},
			expectValue: ptrTrue,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.c.MergeClusterMonitoringCRD(tc.cm)
			if tc.expectValue != nil {
				require.NotNil(t, tc.c.ClusterMonitoringConfiguration)
				require.NotNil(t, tc.c.ClusterMonitoringConfiguration.UserWorkloadEnabled)
				require.Equal(t, *tc.expectValue, *tc.c.ClusterMonitoringConfiguration.UserWorkloadEnabled)
			}
		})
	}
}

func TestConfig_MergeClusterMonitoringCRD_MetricsServerConfigPhase1(t *testing.T) {
	t.Run("CR applies when ConfigMap left MetricsServerConfig nil", func(t *testing.T) {
		c := &Config{
			ClusterMonitoringConfiguration: &ClusterMonitoringConfiguration{},
		}
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				MetricsServerConfig: configv1alpha1.MetricsServerConfig{
					Verbosity: configv1alpha1.VerbosityLevelInfo,
				},
			},
		}
		c.MergeClusterMonitoringCRD(cm)
		require.NotNil(t, c.ClusterMonitoringConfiguration.MetricsServerConfig)
		require.Equal(t, uint8(2), c.ClusterMonitoringConfiguration.MetricsServerConfig.Verbosity)
	})
	t.Run("CR ignored when ConfigMap already set MetricsServerConfig", func(t *testing.T) {
		c := &Config{
			ClusterMonitoringConfiguration: &ClusterMonitoringConfiguration{
				MetricsServerConfig: &MetricsServerConfig{
					Verbosity: 1,
				},
			},
		}
		cm := &configv1alpha1.ClusterMonitoring{
			Spec: configv1alpha1.ClusterMonitoringSpec{
				MetricsServerConfig: configv1alpha1.MetricsServerConfig{
					Verbosity: configv1alpha1.VerbosityLevelInfo,
				},
			},
		}
		c.MergeClusterMonitoringCRD(cm)
		require.Equal(t, uint8(1), c.ClusterMonitoringConfiguration.MetricsServerConfig.Verbosity)
	})
}

func TestConfig_EnsureSafeDefaults(t *testing.T) {
	t.Run("sets UserWorkloadEnabled to false when nil", func(t *testing.T) {
		c := &Config{ClusterMonitoringConfiguration: &ClusterMonitoringConfiguration{}}
		c.EnsureSafeDefaults()
		require.NotNil(t, c.ClusterMonitoringConfiguration.UserWorkloadEnabled)
		require.False(t, *c.ClusterMonitoringConfiguration.UserWorkloadEnabled)
	})
	t.Run("sets MetricsServerConfig with Audit default when nil", func(t *testing.T) {
		c := &Config{ClusterMonitoringConfiguration: &ClusterMonitoringConfiguration{}}
		c.EnsureSafeDefaults()
		require.NotNil(t, c.ClusterMonitoringConfiguration.MetricsServerConfig)
		require.NotNil(t, c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit)
		require.NotEmpty(t, c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit.Profile)
	})
	t.Run("no-op when ClusterMonitoringConfiguration is nil", func(t *testing.T) {
		c := &Config{}
		c.EnsureSafeDefaults()
		require.Nil(t, c.ClusterMonitoringConfiguration)
	})
}
