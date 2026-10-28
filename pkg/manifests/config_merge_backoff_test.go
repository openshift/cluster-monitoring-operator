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

func TestConfig_RemoteWriteBackoffMilliseconds(t *testing.T) {
	for _, tc := range []struct {
		name         string
		queue        configv1alpha1.QueueConfig
		configMapMin string
		configMapMax string
	}{
		{name: "queue omitted"},
		{name: "backoff omitted in configured queue", queue: configv1alpha1.QueueConfig{Capacity: 10000}},
		{name: "minimum only", queue: configv1alpha1.QueueConfig{MinBackoffMilliseconds: 30}, configMapMin: "30ms"},
		{name: "maximum only", queue: configv1alpha1.QueueConfig{MaxBackoffMilliseconds: 5000}, configMapMax: "5s"},
		{name: "typical retry range", queue: configv1alpha1.QueueConfig{MinBackoffMilliseconds: 30, MaxBackoffMilliseconds: 5000}, configMapMin: "30ms", configMapMax: "5s"},
		{name: "composite duration", queue: configv1alpha1.QueueConfig{MinBackoffMilliseconds: 1500, MaxBackoffMilliseconds: 5000}, configMapMin: "1s500ms", configMapMax: "5s"},
		{name: "minimum bounds", queue: configv1alpha1.QueueConfig{MinBackoffMilliseconds: 1, MaxBackoffMilliseconds: 1}, configMapMin: "1ms", configMapMax: "1ms"},
		{name: "maximum bounds", queue: configv1alpha1.QueueConfig{MinBackoffMilliseconds: 3600000, MaxBackoffMilliseconds: 3600000}, configMapMin: "1h", configMapMax: "1h"},
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
			require.Equal(t, int(tc.queue.Capacity), queue.Capacity)
			if tc.configMapMin == "" && tc.configMapMax == "" {
				require.Nil(t, queue.MinBackoff)
				require.Nil(t, queue.MaxBackoff)
				return
			}
			legacy, err := NewConfigFromString(fmt.Sprintf("prometheusK8s:\n  remoteWrite:\n  - name: rw\n    url: https://remote.example.com/write\n    queueConfig:\n      minBackoff: %q\n      maxBackoff: %q\n", tc.configMapMin, tc.configMapMax))
			require.NoError(t, err)
			legacyQueue := legacy.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite[0].QueueConfig
			if tc.configMapMin == "" {
				require.Nil(t, queue.MinBackoff)
			} else {
				require.NotNil(t, queue.MinBackoff)
				actual, err := time.ParseDuration(string(*queue.MinBackoff))
				require.NoError(t, err)
				expected, err := time.ParseDuration(string(*legacyQueue.MinBackoff))
				require.NoError(t, err)
				require.Equal(t, expected, actual)
			}
			if tc.configMapMax == "" {
				require.Nil(t, queue.MaxBackoff)
			} else {
				require.NotNil(t, queue.MaxBackoff)
				actual, err := time.ParseDuration(string(*queue.MaxBackoff))
				require.NoError(t, err)
				expected, err := time.ParseDuration(string(*legacyQueue.MaxBackoff))
				require.NoError(t, err)
				require.Equal(t, expected, actual)
			}
		})
	}
}
