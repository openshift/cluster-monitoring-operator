// Copyright 2024 The Cluster Monitoring Operator Authors
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

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/test_command"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDocExamples(t *testing.T) {
	filesDir := "test_command/scripts/"
	tempDir := t.TempDir()
	kubeConfigPath := f.KubeConfigPath

	entries, err := os.ReadDir(filesDir)
	require.NoError(t, err)
	// In case there is a wiring issue.
	require.Greater(t, len(entries), 0)

	for _, entry := range entries {
		file, err := os.Open(filepath.Join(filesDir, entry.Name()))
		require.NoError(t, err)
		defer file.Close()

		var suite test_command.Suite
		decoder := yaml.NewDecoder(file)
		decoder.KnownFields(true)
		err = decoder.Decode(&suite)
		require.NoError(t, err)

		for _, test := range suite.Tests {
			// TODO: run in //
			t.Run(entry.Name(), func(t *testing.T) {
				// Set up cleaners
				t.Cleanup(func() {
					for _, c := range test.TearDown {
						c.Run(t, tempDir, kubeConfigPath)
					}
				})

				// Setup
				envVars := map[string]string{}
				for _, setup := range test.SetUp {
					require.NoError(t, setup.Run(t, tempDir, kubeConfigPath))
					if setup.EnvVarValue() == "" {
						continue
					}
					// Check duplicated env vars.
					require.NotContains(t, envVars, setup.EnvVar)
					envVars[setup.EnvVar] = setup.EnvVarValue()
				}

				// Run the checks
				for _, g := range test.Checks {
					require.NoError(t, g.Run(t, tempDir, kubeConfigPath, envVars))
				}
			})
		}
	}
}
