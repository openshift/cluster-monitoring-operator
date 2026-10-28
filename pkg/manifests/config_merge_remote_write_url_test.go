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

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/stretchr/testify/require"
)

func TestConfig_RemoteWriteURLQueryParameters(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
	}{
		{name: "simple query", url: "https://remote.example.com/write?tenant=example"},
		{name: "multiple query parameters", url: "https://remote.example.com/write?tenant=example&region=eu"},
		{name: "escaped query parameters", url: "https://remote.example.com/write?tenant=team%2Fa&filter=a%26b%3Dc"},
		{name: "http query parameters", url: "http://remote.example.com/write?tenant=example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cr := &configv1alpha1.ClusterMonitoring{
				Spec: configv1alpha1.ClusterMonitoringSpec{
					PrometheusConfig: configv1alpha1.PrometheusConfig{
						RemoteWrite: []configv1alpha1.RemoteWriteSpec{{Name: "rw", URL: tc.url}},
					},
				},
			}
			merged, err := NewConfigFromStringAndClusterMonitoringResource("{}", cr)
			require.NoError(t, err)
			actual := merged.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite
			require.Len(t, actual, 1)
			require.Equal(t, tc.url, actual[0].URL)

			// Migration must preserve the exact URL, including escaping and parameter order.
			legacy, err := NewConfigFromString(fmt.Sprintf("prometheusK8s:\n  remoteWrite:\n  - name: rw\n    url: %q\n", tc.url))
			require.NoError(t, err)
			expected := legacy.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite
			require.Len(t, expected, 1)
			require.Equal(t, expected[0].URL, actual[0].URL)
		})
	}
}
