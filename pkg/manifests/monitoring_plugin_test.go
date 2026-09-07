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
	"slices"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/require"
)

func TestMonitoringPluginDeploymentDisabledFeatures(t *testing.T) {
	defaultDeployment, err := newMonitoringPluginTestFactory(mustDefaultConfig()).MonitoringPluginDeployment()
	require.NoError(t, err)

	for _, tc := range []struct {
		name             string
		disabledFeatures []string
		expectedArgument string
		expectedError    string
	}{
		{
			name:             "disable alerting",
			disabledFeatures: []string{"alerting"},
			expectedArgument: "--features=legacy-dashboards,targets,metrics",
		},
		{
			name:             "disable multiple features",
			disabledFeatures: []string{"alerting", "targets"},
			expectedArgument: "--features=legacy-dashboards,metrics",
		},
		{
			name:             "ignore features that are not enabled by default",
			disabledFeatures: []string{"alerting-management"},
			expectedArgument: "--features=alerting,legacy-dashboards,targets,metrics",
		},
		{
			name:             "require at least one feature",
			disabledFeatures: []string{"alerting", "legacy-dashboards", "targets", "metrics"},
			expectedError:    "monitoring plugin must have at least one feature enabled",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustDefaultConfig()
			cfg.ClusterMonitoringConfiguration.MonitoringPluginConfig = &MonitoringPluginConfig{
				DisabledFeatures: tc.disabledFeatures,
			}
			deployment, err := newMonitoringPluginTestFactory(cfg).MonitoringPluginDeployment()
			if tc.expectedError != "" {
				require.ErrorContains(t, err, tc.expectedError)
				return
			}
			require.NoError(t, err)

			expectedDeployment := defaultDeployment.DeepCopy()
			containerIndex := slices.IndexFunc(expectedDeployment.Spec.Template.Spec.Containers, containerNameEquals(MonitoringPluginDeploymentContainer))
			require.NotEqual(t, -1, containerIndex)

			args := expectedDeployment.Spec.Template.Spec.Containers[containerIndex].Args
			featuresArgIndex := slices.IndexFunc(args, func(arg string) bool {
				return strings.HasPrefix(arg, MonitoringPluginFeaturesFlag)
			})
			require.NotEqual(t, -1, featuresArgIndex)
			args[featuresArgIndex] = tc.expectedArgument

			require.Equal(t, expectedDeployment, deployment)
		})
	}
}

func newMonitoringPluginTestFactory(cfg *Config) *Factory {
	return NewFactory(
		"openshift-monitoring",
		"openshift-user-workload-monitoring",
		cfg,
		defaultInfrastructureReader(),
		&fakeProxyReader{},
		NewAssets(assetsPath),
		&APIServerConfig{},
		&configv1.Console{},
	)
}
