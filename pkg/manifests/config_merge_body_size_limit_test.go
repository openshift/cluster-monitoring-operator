// Copyright 2026 The Cluster Monitoring Operator Authors.
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
	"testing"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/stretchr/testify/require"
)

func TestMergeBodySizeLimitModes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      configv1alpha1.EnforcedBodySizeLimitMode
		bytes     int64
		configMap string
		want      string
	}{
		{name: "automatic", mode: configv1alpha1.EnforcedBodySizeLimitModeAutomatic, want: automaticBodySizeLimit},
		{name: "disabled", mode: configv1alpha1.EnforcedBodySizeLimitModeDisabled},
		{name: "explicit", mode: configv1alpha1.EnforcedBodySizeLimitModeExplicit, bytes: 4194304, want: "4194304B"},
		{name: "legacy bytes", bytes: 4194304, want: "4194304B"},
		{name: "omitted"},
		{name: "ConfigMap overrides automatic", mode: configv1alpha1.EnforcedBodySizeLimitModeAutomatic, configMap: "prometheusK8s:\n  enforcedBodySizeLimit: 8MB", want: "8MB"},
		{name: "ConfigMap overrides disabled", mode: configv1alpha1.EnforcedBodySizeLimitModeDisabled, configMap: "prometheusK8s:\n  enforcedBodySizeLimit: automatic", want: automaticBodySizeLimit},
		{name: "ConfigMap overrides explicit", mode: configv1alpha1.EnforcedBodySizeLimitModeExplicit, bytes: 4194304, configMap: "prometheusK8s:\n  enforcedBodySizeLimit: 8MB", want: "8MB"},
		{name: "ConfigMap empty section overrides automatic", mode: configv1alpha1.EnforcedBodySizeLimitModeAutomatic, configMap: "prometheusK8s: {}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := configv1alpha1.PrometheusConfig{
				EnforcedBodySizeLimitMode:  tc.mode,
				EnforcedBodySizeLimitBytes: tc.bytes,
			}
			require.Equal(t, tc.mode == "" && tc.bytes == 0, clusterMonitoringPrometheusSpecEmpty(pc))
			cm := &configv1alpha1.ClusterMonitoring{Spec: configv1alpha1.ClusterMonitoringSpec{PrometheusConfig: pc}}
			input := tc.configMap
			if input == "" {
				input = "{}"
			}
			c, err := NewConfigFromStringAndClusterMonitoringResource(input, cm)
			require.NoError(t, err)
			require.Equal(t, tc.want, c.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit)
			if tc.mode == configv1alpha1.EnforcedBodySizeLimitModeAutomatic && tc.configMap == "" {
				capacity := &fakePodCapacity{capacity: 1000}
				require.NoError(t, c.LoadEnforcedBodySizeLimit(capacity, context.Background()))
				require.Equal(t, calculateBodySizeLimit(1000), c.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit)
			}
		})
	}
}

func TestMergeBodySizeLimitUnknownMode(t *testing.T) {
	cm := &configv1alpha1.ClusterMonitoring{Spec: configv1alpha1.ClusterMonitoringSpec{
		PrometheusConfig: configv1alpha1.PrometheusConfig{EnforcedBodySizeLimitMode: "Unknown"},
	}}
	_, err := NewConfigFromStringAndClusterMonitoringResource("{}", cm)
	require.ErrorContains(t, err, "unsupported enforcedBodySizeLimitMode")
}
