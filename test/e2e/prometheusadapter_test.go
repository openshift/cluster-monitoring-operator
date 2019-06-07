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
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	apiservicesv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
)

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
	var lastErr error
	err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		metricsService, err := f.APIServicesClient.ApiregistrationV1().APIServices().Get("v1beta1.metrics.k8s.io", metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting metrics APIService failed")
		if err != nil {
			return false, nil
		}
		if !isAPIServiceAvailable(metricsService.Status.Conditions) {
			lastErr = errors.New("v1beta1.metrics.k8s.io apiservice is not available")
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
	var lastErr error
	err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		nodes, err := f.KubeClient.CoreV1().Nodes().List(metav1.ListOptions{})
		lastErr = errors.Wrap(err, "getting nodes list failed")
		if err != nil {
			return false, nil
		}
		nodeMetrics, err := f.MetricsClient.MetricsV1beta1().NodeMetricses().List(metav1.ListOptions{})
		lastErr = errors.Wrap(err, "getting metrics list failed")
		if err != nil {
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
	err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		pods, err := f.KubeClient.CoreV1().Pods("").List(metav1.ListOptions{FieldSelector: "status.phase=Running"})
		lastErr = errors.Wrap(err, "getting pods list failed")
		if err != nil {
			return false, nil
		}
		podMetrics, err := f.MetricsClient.MetricsV1beta1().PodMetricses("").List(metav1.ListOptions{})
		lastErr = errors.Wrap(err, "getting metrics list failed")
		if err != nil {
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
	present := func(where []string, what string) bool {
		sort.Strings(where)
		i := sort.SearchStrings(where, what)
		return i < len(where) && where[i] == what
	}

	type checkFunc func(clusterRole string) error

	hasRule := func(apiGroup, resource, verb string) checkFunc {
		return func(clusterRole string) error {
			return framework.Poll(time.Second, 5*time.Minute, func() error {
				viewRole, err := f.KubeClient.RbacV1().ClusterRoles().Get(clusterRole, metav1.GetOptions{})
				if err != nil {
					return errors.Wrapf(err, "getting %s cluster role failed", clusterRole)
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

func TestPrometheusAdapterCARotation(t *testing.T) {
	var lastErr error
	// Wait for Prometheus adapter
	err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		_, err := f.KubeClient.AppsV1().Deployments(f.Ns).Get("prometheus-adapter", metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting prometheus-adapter deployment failed")
		if err != nil {
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

	apiAuth, err := f.KubeClient.CoreV1().ConfigMaps("kube-system").Get("extension-apiserver-authentication", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	tls, err := f.KubeClient.CoreV1().Secrets("openshift-monitoring").Get("prometheus-adapter-tls", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Simulate rotation by simply adding a newline to existing certs.
	// This change will be propagated to the cluster monitoring operator,
	// causing a new secret to be created.
	apiAuth.Data["requestheader-client-ca-file"] = apiAuth.Data["requestheader-client-ca-file"] + "\n"
	apiAuth, err = f.KubeClient.CoreV1().ConfigMaps("kube-system").Update(apiAuth)
	if err != nil {
		t.Fatal(err)
	}

	factory := manifests.NewFactory("openshift-monitoring", nil)
	newSecret, err := factory.PrometheusAdapterSecret(tls, apiAuth)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the new secret to be created
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		_, err := f.KubeClient.CoreV1().Secrets(f.Ns).Get(newSecret.Name, metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting new api auth secret failed")
		if err != nil {
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

	// Wait for new Prometheus adapter to roll out
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		d, err := f.KubeClient.AppsV1().Deployments(f.Ns).Get("prometheus-adapter", metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting new prometheus adapter deployment failed")
		if err != nil {
			return false, nil
		}

		lastErr = fmt.Errorf("waiting for updated replica count=%d to be spec replica count=%d", d.Status.UpdatedReplicas, *d.Spec.Replicas)
		return d.Status.UpdatedReplicas == *d.Spec.Replicas, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		t.Fatal(err)
	}
}
