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

func TestConfig_RemoteWriteBatchSendDeadlineSeconds(t *testing.T) {
	for _, tc := range []struct {
		name              string
		queue             configv1alpha1.QueueConfig
		configMapDuration string
	}{
		{name: "queue omitted"},
		{name: "deadline omitted in configured queue", queue: configv1alpha1.QueueConfig{Capacity: 10000}},
		{name: "minimum", queue: configv1alpha1.QueueConfig{BatchSendDeadlineSeconds: 1}, configMapDuration: "1s"},
		{name: "five seconds", queue: configv1alpha1.QueueConfig{BatchSendDeadlineSeconds: 5}, configMapDuration: "5s"},
		{name: "minutes", queue: configv1alpha1.QueueConfig{BatchSendDeadlineSeconds: 120}, configMapDuration: "2m"},
		{name: "maximum", queue: configv1alpha1.QueueConfig{BatchSendDeadlineSeconds: 3600}, configMapDuration: "1h"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cr := &configv1alpha1.ClusterMonitoring{
				Spec: configv1alpha1.ClusterMonitoringSpec{
					PrometheusConfig: configv1alpha1.PrometheusConfig{
						RemoteWrite: []configv1alpha1.RemoteWriteSpec{{
							Name: "rw", URL: "https://remote.example.com/write", QueueConfig: tc.queue,
						}},
					},
				},
			}
			merged, err := NewConfigFromStringAndClusterMonitoringResource("{}", cr)
			require.NoError(t, err)
			remoteWrite := merged.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite
			require.Len(t, remoteWrite, 1)
			queue := remoteWrite[0].QueueConfig
			if tc.queue == (configv1alpha1.QueueConfig{}) {
				require.Nil(t, queue)
				return
			}
			require.NotNil(t, queue)
			if tc.configMapDuration == "" {
				require.Nil(t, queue.BatchSendDeadline)
				require.Equal(t, int(tc.queue.Capacity), queue.Capacity)
				return
			}
			require.NotNil(t, queue.BatchSendDeadline)
			legacy, err := NewConfigFromString(fmt.Sprintf("prometheusK8s:\n  remoteWrite:\n  - name: rw\n    url: https://remote.example.com/write\n    queueConfig:\n      batchSendDeadline: %q\n", tc.configMapDuration))
			require.NoError(t, err)
			actual, err := time.ParseDuration(string(*queue.BatchSendDeadline))
			require.NoError(t, err)
			expected, err := time.ParseDuration(string(*legacy.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite[0].QueueConfig.BatchSendDeadline))
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		})
	}
}
