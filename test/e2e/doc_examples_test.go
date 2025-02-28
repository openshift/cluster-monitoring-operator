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
	"hash/fnv"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/test_command"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testNamespace      = "test-doc-examples-in-cluster"
	serviceAccount     = "tester"
	clusterRoleBinding = "tester"
)

func toPodName(testName string) string {
	h := fnv.New64()
	h.Write([]byte(testName))
	return "test-" + strconv.FormatUint(h.Sum64(), 32)
}

func setupEnv(t *testing.T) {
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

	cleanupBinding, err := f.CreateClusterRoleBinding(testNamespace, clusterRoleBinding, "cluster-admin")
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
	require.Greater(t, len(scripts), 3)
	setupEnv(t)

	for _, script := range scripts {
		t.Run(script.Name(), func(t *testing.T) {
			t.Parallel()
			file, err := os.Open(filepath.Join(filesDir, script.Name()))
			require.NoError(t, err)
			defer file.Close()

			var suite test_command.Suite
			decoder := yaml.NewDecoder(file)
			decoder.KnownFields(true)
			require.NoError(t, decoder.Decode(&suite))

			for i, test := range suite.Tests {
				// Run the script inside a Pod as some of the endpoints are not exposed by default.
				t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
					t.Parallel()
					t.Cleanup(func() {
						test_command.RunScript(t, test.TearDown, tempDir, kubeConfigPath)
					})

					ctx := context.Background()
					podName := toPodName(t.Name())
					containerName := "test"
					pod := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      podName,
							Namespace: testNamespace,
						},
						Spec: corev1.PodSpec{
							ServiceAccountName: serviceAccount,
							RestartPolicy:      corev1.RestartPolicyNever,
							Containers: []corev1.Container{
								{
									Name:            containerName,
									Image:           "registry.redhat.io/openshift4/ose-cli:latest",
									ImagePullPolicy: corev1.PullIfNotPresent,
									Command:         []string{"bash", "-c", test.Script},
									SecurityContext: &corev1.SecurityContext{
										Capabilities: &corev1.Capabilities{
											Drop: []corev1.Capability{"ALL"},
										},
										SeccompProfile: &v1.SeccompProfile{
											Type: v1.SeccompProfileTypeRuntimeDefault,
										},
									},
								},
							},
						},
					}

					pod, err := f.KubeClient.CoreV1().Pods(testNamespace).Create(ctx, pod, metav1.CreateOptions{})
					require.NoError(t, err)
					t.Cleanup(func() {
						err := f.KubeClient.CoreV1().Pods(testNamespace).Delete(context.Background(), podName, metav1.DeleteOptions{})
						require.NoError(t, err)
					})

					err = framework.Poll(time.Second, time.Minute, func() error {
						pod, err = f.KubeClient.CoreV1().Pods(testNamespace).Get(ctx, podName, metav1.GetOptions{})
						if err != nil {
							return err
						}
						if pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed {
							return fmt.Errorf("waiting for pod")
						}
						return nil
					})

					if pod.Status.Phase != corev1.PodSucceeded {
						l, err := f.GetLogs(testNamespace, podName, containerName)
						require.NoError(t, err)
						t.Log(l)
						require.Fail(t, "pod failed to execute script")
					}
				})
			}
		})
	}
}
