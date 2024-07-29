// Copyright 2019 The Cluster Monitoring Operator Authors
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
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	apiservicesv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
)

const MetricsServerFeatureGate string = "MetricsServer"

func skipMetricsServerTests(t *testing.T) {
	if !f.IsFeatureGateEnabled(t, MetricsServerFeatureGate) {
		t.Skip("Skipping Metrics Server test")
	}
}

func isAPIServicePointingToRightMetricsService(t *testing.T, metricsService *apiservicesv1.APIService) bool {
	return metricsService.Spec.Service.Name == "metrics-server"
}

func isNodeInNodesList(node string, nodes []corev1.Node) bool {
	for _, n := range nodes {
		if n.Name == node {
			return true
		}
	}
	return false
}

func isPodInPodsList(pod string, ns string, pods []corev1.Pod) bool {
	for _, p := range pods {
		if p.Name == pod && p.Namespace == ns {
			return true
		}
	}
	return false
}

func isAPIServiceAvailable(conditions []apiservicesv1.APIServiceCondition) bool {
	for _, condition := range conditions {
		if condition.Type == apiservicesv1.Available && condition.Status == apiservicesv1.ConditionTrue {
			return true
		}
	}
	return false
}

func TestMetricsAPIAvailability(t *testing.T) {
	ctx := context.Background()
	var lastErr error
	err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		metricsService, err := f.APIServicesClient.ApiregistrationV1().APIServices().Get(ctx, "v1beta1.metrics.k8s.io", metav1.GetOptions{})
		if err != nil {
			lastErr = fmt.Errorf("getting metrics APIService failed: %w", err)
			return false, nil
		}
		if !isAPIServiceAvailable(metricsService.Status.Conditions) {
			lastErr = errors.New("v1beta1.metrics.k8s.io apiservice is not available")
			return false, nil
		}
		if metricsService.Spec.Service.Name != "metrics-server" {
			lastErr = errors.New("v1beta1.metrics.k8s.io apiservice is not pointing to right metrics api service")
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		t.Fatal(err)
	}
}

func TestNodeMetricsPresence(t *testing.T) {
	ctx := context.Background()
	var lastErr error
	err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		nodes, err := f.KubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			lastErr = fmt.Errorf("getting nodes list failed: %w", err)
			return false, nil
		}
		nodeMetrics, err := f.MetricsClient.MetricsV1beta1().NodeMetricses().List(ctx, metav1.ListOptions{})
		if err != nil {
			lastErr = fmt.Errorf("getting metrics list failed: %w", err)
			return false, nil
		}
		if len(nodes.Items) != len(nodeMetrics.Items) {
			lastErr = errors.New("number of nodes doesn't match number of node metrics reported")
			return false, nil
		}
		for _, item := range nodeMetrics.Items {
			if !isNodeInNodesList(item.Name, nodes.Items) {
				lastErr = errors.New("node reporting metrics couldn't be found in nodes list")
				return false, nil
			}
			if item.Usage.Cpu() == nil || item.Usage.Memory() == nil {
				lastErr = errors.New("node cpu or memory metric not found")
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		t.Fatal(err)
	}
}

func TestPodMetricsPresence(t *testing.T) {
	var lastErr error
	ctx := context.Background()
	err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		pods, err := f.KubeClient.CoreV1().Pods("").List(ctx, metav1.ListOptions{FieldSelector: "status.phase=Running"})
		if err != nil {
			lastErr = fmt.Errorf("getting pods list failed: %w", err)
			return false, nil
		}
		podMetrics, err := f.MetricsClient.MetricsV1beta1().PodMetricses("").List(ctx, metav1.ListOptions{})
		if err != nil {
			lastErr = fmt.Errorf("getting metrics list failed: %w", err)
			return false, nil
		}
		if len(pods.Items) != len(podMetrics.Items) {
			lastErr = fmt.Errorf("number of running pods (%d) doesn't match number of pods reporting metrics (%d)", len(pods.Items), len(podMetrics.Items))
			return false, nil
		}

		for _, pod := range podMetrics.Items {
			if !isPodInPodsList(pod.Name, pod.Namespace, pods.Items) {
				lastErr = errors.New("pod reporting metrics couldn't be found in pods list")
				return false, nil
			}
			for _, item := range pod.Containers {
				if item.Usage.Cpu() == nil || item.Usage.Memory() == nil {
					lastErr = errors.New("container cpu or memory metric not found")
					return false, nil
				}
			}
		}
		return true, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		t.Fatal(err)
	}
}

func TestAggregatedMetricPermissions(t *testing.T) {
	ctx := context.Background()
	present := func(where []string, what string) bool {
		sort.Strings(where)
		i := sort.SearchStrings(where, what)
		return i < len(where) && where[i] == what
	}

	type checkFunc func(clusterRole string) error

	hasRule := func(apiGroup, resource, verb string) checkFunc {
		return func(clusterRole string) error {
			return framework.Poll(time.Second, 5*time.Minute, func() error {
				viewRole, err := f.KubeClient.RbacV1().ClusterRoles().Get(ctx, clusterRole, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("getting %s cluster role failed: %w", clusterRole, err)
				}

				for _, rule := range viewRole.Rules {
					if !present(rule.APIGroups, apiGroup) {
						continue
					}

					if !present(rule.Resources, resource) {
						continue
					}

					if !present(rule.Verbs, verb) {
						continue
					}

					return nil
				}

				return fmt.Errorf("could not find metrics in cluster role %s", clusterRole)
			})
		}
	}

	canGetPodMetrics := hasRule("metrics.k8s.io", "pods", "get")

	for _, tc := range []struct {
		clusterRole string
		check       checkFunc
	}{
		{
			clusterRole: "view",
			check:       canGetPodMetrics,
		},
		{
			clusterRole: "edit",
			check:       canGetPodMetrics,
		},
		{
			clusterRole: "admin",
			check:       canGetPodMetrics,
		},
	} {
		t.Run(tc.clusterRole, func(t *testing.T) {
			if err := tc.check(tc.clusterRole); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestMetricsServerRollout(t *testing.T) {
	skipMetricsServerTests(t)
	for _, test := range []scenario{
		{
			name:      "assert metrics-server deployment is rolled out",
			assertion: f.AssertDeploymentExistsAndRollout("metrics-server", f.Ns),
		},
		{
			name:      "assert metrics-server service is created",
			assertion: f.AssertServiceExists("metrics-server", f.Ns),
		},
		{
			name:      "assert metrics-server service monitor is created",
			assertion: f.AssertServiceMonitorExists("metrics-server", f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/name=metrics-server,app.kubernetes.io/component=metrics-server",
				[]framework.PodAssertion{
					expectContainerArg("--metric-resolution=15s", "metrics-server"),
				},
			),
		},
		{
			name:      "assert prometheus-adapter service monitor is deleted",
			assertion: f.AssertServiceMonitorDoesNotExist("prometheus-adapter", f.Ns),
		},
		{
			name:      "assert prometheus-adapter service is deleted",
			assertion: f.AssertServiceDoesNotExist("prometheus-adapter", f.Ns),
		},
		{
			name:      "assert prometheus-adapter deployment is deleted",
			assertion: f.AssertDeploymentDoesNotExist("prometheus-adapter", f.Ns),
		},
	} {
		t.Run(test.name, test.assertion)
	}
}
