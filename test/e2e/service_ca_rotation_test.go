// Copyright 2021 The Cluster Monitoring Operator Authors
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
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
)

func TestServiceCASecretRotation(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name       string
		secretName string
	}{
		{
			name:       "monitoring-plugin-cert change is handled gracefully",
			secretName: "monitoring-plugin-cert",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := f.KubeClient.CoreV1().Secrets(f.Ns).Get(ctx, tc.secretName, metav1.GetOptions{})
			if err != nil {
				t.Skipf("secret %s/%s not found, skipping test: %v", f.Ns, tc.secretName, err)
			}

			t.Cleanup(func() {
				if s, err := f.KubeClient.CoreV1().Secrets(f.Ns).Get(ctx, tc.secretName, metav1.GetOptions{}); err == nil && s.Annotations != nil {
					if _, exists := s.Annotations["test.openshift.io/service-ca-test-rotation"]; exists {
						delete(s.Annotations, "test.openshift.io/service-ca-test-rotation")
						_ = f.OperatorClient.CreateOrUpdateSecret(ctx, s)
					}
				}
			})

			initialCO, err := f.OpenShiftConfigClient.ConfigV1().ClusterOperators().Get(ctx, "monitoring", metav1.GetOptions{})
			if err != nil {
				t.Fatalf("error getting initial cluster operator status: %v", err)
			}

			if s.Annotations == nil {
				s.Annotations = make(map[string]string)
			}
			s.Annotations["test.openshift.io/service-ca-test-rotation"] = fmt.Sprintf("%d", time.Now().Unix())

			if err := f.OperatorClient.CreateOrUpdateSecret(ctx, s); err != nil {
				t.Fatalf("error updating secret %s/%s: %v", f.Ns, tc.secretName, err)
			}

			err = framework.Poll(5*time.Second, 2*time.Minute, func() error {
				co, err := f.OpenShiftConfigClient.ConfigV1().ClusterOperators().Get(ctx, "monitoring", metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("error getting cluster operator status: %w", err)
				}

				for _, condition := range co.Status.Conditions {
					switch condition.Type {
					case "Available":
						if condition.Status != "True" {
							return fmt.Errorf("cluster operator is not available: %s", condition.Message)
						}
					case "Degraded":
						if condition.Status == "True" {
							return fmt.Errorf("cluster operator is degraded: %s", condition.Message)
						}
					case "Progressing":
						if condition.Status == "True" && condition.Reason != "" {
							if co.Generation == initialCO.Generation {
								return fmt.Errorf("operator is progressing but generation hasn't changed")
							}
						}
					}
				}

				return nil
			})
			if err != nil {
				t.Fatalf("service-CA secret rotation test failed: %v", err)
			}
		})
	}
}
