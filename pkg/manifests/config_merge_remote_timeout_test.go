// Copyright 2026 The Cluster Monitoring Operator Authors
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
	"fmt"
	"testing"
	"time"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/stretchr/testify/require"
)

func TestConfig_RemoteWriteTimeoutSeconds(t *testing.T) {
	for _, tc := range []struct {
		name              string
		seconds           int32
		configMapDuration string
	}{
		{name: "omitted"},
		{name: "minimum", seconds: 1, configMapDuration: "1s"},
		{name: "thirty seconds", seconds: 30, configMapDuration: "30s"},
		{name: "minutes", seconds: 120, configMapDuration: "2m"},
		{name: "maximum", seconds: 600, configMapDuration: "10m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cr := &configv1alpha1.ClusterMonitoring{
				Spec: configv1alpha1.ClusterMonitoringSpec{
					PrometheusConfig: configv1alpha1.PrometheusConfig{
						RemoteWrite: []configv1alpha1.RemoteWriteSpec{{
							Name: "rw", URL: "https://remote.example.com/write", RemoteTimeoutSeconds: tc.seconds,
						}},
					},
				},
			}
			merged, err := NewConfigFromStringAndClusterMonitoringResource("{}", cr)
			require.NoError(t, err)
			remoteWrite := merged.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite
			require.Len(t, remoteWrite, 1)
			if tc.configMapDuration == "" {
				require.Empty(t, remoteWrite[0].RemoteTimeout)
				return
			}
			// The integer API and the ConfigMap duration must describe the same timeout.
			legacy, err := NewConfigFromString(fmt.Sprintf("prometheusK8s:\n  remoteWrite:\n  - name: rw\n    url: https://remote.example.com/write\n    remoteTimeout: %q\n", tc.configMapDuration))
			require.NoError(t, err)
			actual, err := time.ParseDuration(remoteWrite[0].RemoteTimeout)
			require.NoError(t, err)
			expected, err := time.ParseDuration(legacy.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite[0].RemoteTimeout)
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		})
	}
}
