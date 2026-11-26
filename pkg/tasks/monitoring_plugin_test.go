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

package tasks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

func TestMonitoringPluginTaskAlertsManagementAPIEnabled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		config   string
		expected bool
	}{
		{
			name:     "no plugin config",
			config:   "",
			expected: false,
		},
		{
			name: "plugin config without the feature",
			config: `monitoringPlugin:
  nodeSelector:
    type: master
`,
			expected: false,
		},
		{
			name: "the alerts management API feature is enabled",
			config: `monitoringPlugin:
  unsupportedFeatures:
    - alert-management-api
`,
			expected: true,
		},
		{
			name: "another feature is enabled",
			config: `monitoringPlugin:
  unsupportedFeatures:
    - some-other-feature
`,
			expected: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := manifests.NewConfigFromString(tc.config)
			require.NoError(t, err)

			task := NewMonitoringPluginTask(nil, nil, c)
			require.Equal(t, tc.expected, task.alertsManagementAPIEnabled())
		})
	}
}

func TestMonitoringPluginTaskUserWorkloadMonitoringEnabled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		config   string
		expected bool
	}{
		{
			name:     "no config",
			config:   "",
			expected: false,
		},
		{
			name: "user workload monitoring disabled",
			config: `enableUserWorkload: false
`,
			expected: false,
		},
		{
			name: "user workload monitoring enabled",
			config: `enableUserWorkload: true
`,
			expected: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := manifests.NewConfigFromString(tc.config)
			require.NoError(t, err)

			task := NewMonitoringPluginTask(nil, nil, c)
			require.Equal(t, tc.expected, task.userWorkloadMonitoringEnabled())
		})
	}
}
