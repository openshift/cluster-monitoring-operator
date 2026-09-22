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
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testNamespace      = "test-doc-examples-in-cluster"
	serviceAccount     = "tester"
	clusterRoleBinding = "tester"
)

func toJobName(testName string) string {
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

	require.NoError(t, f.WaitForNamespaceSCCAnnotation(testNamespace))
	require.NoError(t, f.WaitForServiceAccountImagePullSecrets(testNamespace, serviceAccount))
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
				// Run the script inside a Job so that transient errors
				// (e.g. connection refused during pod restarts) are
				// retried automatically via backoffLimit.
				t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
					t.Parallel()
					t.Cleanup(func() {
						test_command.RunScript(t, test.TearDown, tempDir, kubeConfigPath)
					})

					ctx := context.Background()
					jobName := toJobName(t.Name())
					containerName := "test"
					var backoffLimit int32 = 5
					job := &batchv1.Job{
						ObjectMeta: metav1.ObjectMeta{
							Name:      jobName,
							Namespace: testNamespace,
						},
						Spec: batchv1.JobSpec{
							BackoffLimit: &backoffLimit,
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									ServiceAccountName: serviceAccount,
									RestartPolicy:      corev1.RestartPolicyOnFailure,
									Containers: []corev1.Container{
										{
											Name:            containerName,
											Image:           "image-registry.openshift-image-registry.svc:5000/openshift/cli:latest",
											ImagePullPolicy: corev1.PullIfNotPresent,
											Command:         []string{"bash", "-c", test.Script},
											SecurityContext: &corev1.SecurityContext{
												Capabilities: &corev1.Capabilities{
													Drop: []corev1.Capability{"ALL"},
												},
												SeccompProfile: &corev1.SeccompProfile{
													Type: corev1.SeccompProfileTypeRuntimeDefault,
												},
											},
										},
									},
								},
							},
						},
					}

					_, err := f.KubeClient.BatchV1().Jobs(testNamespace).Create(ctx, job, metav1.CreateOptions{})
					require.NoError(t, err)
					t.Cleanup(func() {
						if err := f.KubeClient.BatchV1().Jobs(testNamespace).Delete(context.Background(), jobName, metav1.DeleteOptions{}); err != nil {
							t.Logf("failed to delete job %s: %v", jobName, err)
						}
					})

					var completed bool
					err = framework.Poll(5*time.Second, 6*time.Minute, func() error {
						j, err := f.KubeClient.BatchV1().Jobs(testNamespace).Get(ctx, jobName, metav1.GetOptions{})
						if err != nil {
							return err
						}
						for _, c := range j.Status.Conditions {
							if c.Type == batchv1.JobComplete && c.Status == corev1.ConditionTrue {
								completed = true
								return nil
							}
							if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
								return nil
							}
						}
						return fmt.Errorf("waiting for job %s/%s to finish", testNamespace, jobName)
					})
					require.NoError(t, err)

					if !completed {
						// Retrieve logs from all pods created by the job.
						pods, err := f.KubeClient.CoreV1().Pods(testNamespace).List(ctx, metav1.ListOptions{
							LabelSelector: "job-name=" + jobName,
						})
						if err == nil {
							for _, pod := range pods.Items {
								l, _ := f.GetLogs(testNamespace, pod.Name, containerName)
								t.Logf("logs from pod %s: %s", pod.Name, l)
							}
						}
						require.Fail(t, "job failed to execute script")
					}
				})
			}
		})
	}
}
