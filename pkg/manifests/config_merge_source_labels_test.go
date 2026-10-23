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
	"encoding/json"
	"testing"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/stretchr/testify/require"
)

func TestConfig_RemoteWriteEmptySourceLabels(t *testing.T) {
	for _, tc := range []struct {
		name   string
		labels []string
	}{
		{name: "omitted"},
		{name: "explicitly empty", labels: []string{}},
		{name: "non-empty control", labels: []string{"job"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := configv1alpha1.RelabelConfig{
				Name: "keep-rule", SourceLabels: tc.labels, Regex: ".*",
				Action: configv1alpha1.RelabelActionConfig{Type: configv1alpha1.RelabelActionKeep},
			}

			// Typed CR serialization omits empty sourceLabels rather than submitting
			// an explicit empty array, which the API's minItems validation rejects.
			data, err := json.Marshal(rule)
			require.NoError(t, err)
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(data, &fields))
			if len(tc.labels) == 0 {
				require.NotContains(t, fields, "sourceLabels")
			} else {
				require.Contains(t, fields, "sourceLabels")
			}
			var serializedRule configv1alpha1.RelabelConfig
			require.NoError(t, json.Unmarshal(data, &serializedRule))

			for _, input := range []struct {
				name string
				rule configv1alpha1.RelabelConfig
			}{
				{name: "direct merge", rule: rule},
				{name: "serialized CR merge", rule: serializedRule},
			} {
				t.Run(input.name, func(t *testing.T) {
					cr := &configv1alpha1.ClusterMonitoring{
						Spec: configv1alpha1.ClusterMonitoringSpec{
							PrometheusConfig: configv1alpha1.PrometheusConfig{
								RemoteWrite: []configv1alpha1.RemoteWriteSpec{{
									Name: "rw", URL: "https://remote.example.com/write",
									WriteRelabelConfigs: []configv1alpha1.RelabelConfig{input.rule},
								}},
							},
						},
					}
					merged, err := NewConfigFromStringAndClusterMonitoringResource("{}", cr)
					require.NoError(t, err)
					remoteWrite := merged.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite
					require.Len(t, remoteWrite, 1)
					require.Len(t, remoteWrite[0].WriteRelabelConfigs, 1)
					actual := remoteWrite[0].WriteRelabelConfigs[0]
					require.Equal(t, string(configv1alpha1.RelabelActionKeep), actual.Action)
					require.Equal(t, ".*", actual.Regex)
					require.Len(t, actual.SourceLabels, len(tc.labels))
					for i, label := range tc.labels {
						require.EqualValues(t, label, actual.SourceLabels[i])
					}
				})
			}
		})
	}
}
