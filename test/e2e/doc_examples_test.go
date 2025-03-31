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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/test_command"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)


const (
	testNamespace = "test-doc-examples-in-cluster"
	serviceAccount = "tester"
	clusterRoleBinding = "tester"
)


func setUpInClusterTester(t *testing.T) {
	cleanupNS, err := f.CreateNamespace(testNamespace)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, cleanupNS())
	})

	cleanupSA, err := f.CreateServiceAccount(testNamespace, serviceAccount)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, cleanupSA())
	})

	cleanupBinding, err := f.CreateClusterRoleBinding(testNamespace, clusterRoleBinding, "admin")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, cleanupBinding())
	})
}


func TestDocExamples(t *testing.T) {
	filesDir := "test_command/scripts/"
	tempDir := t.TempDir()
	kubeConfigPath := f.KubeConfigPath

	scripts, err := os.ReadDir(filesDir)
	require.NoError(t, err)
	// In case there is a wiring issue.
	require.Greater(t, len(scripts), 0)

	setUpInClusterTester(t)

	for _, script := range scripts {
		t.Run(script.Name(), func(t *testing.T) {
			// TODO
			// t.Parallel()
			file, err := os.Open(filepath.Join(filesDir, script.Name()))
			require.NoError(t, err)
			defer file.Close()

			var suite test_command.Suite
			decoder := yaml.NewDecoder(file)
			decoder.KnownFields(true)
			require.NoError(t, decoder.Decode(&suite))

			for i, test := range suite.Tests {
				t.Run(fmt.Sprintf("suite-%d", i), func(t *testing.T) {
					// TODO
					// t.Parallel()
					t.Cleanup(func() {
						test_command.RunScript(t, test.TearDown, tempDir, kubeConfigPath)
					})

					if test.InCluster {
						ctx := context.Background()

						pod := client.V1Pod{
							Metadata: &client.V1ObjectMeta{
								Name:      "my-pod",
								Namespace: "default",
							},
							Spec: &client.V1PodSpec{
								Containers: []client.V1Container{
									client.V1Container{
										Name:  "www",
										Image: "nginx",
									},
								},
							},
						}
						
					} else {
						test_command.RunScript(t, test.Script, tempDir, kubeConfigPath)
					}
				})
			}
		})
	}
}
