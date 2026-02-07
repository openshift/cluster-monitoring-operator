// Copyright 2025 The Cluster Monitoring Operator Authors
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

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const clusterMonitoringName = "cluster"

func TestClusterMonitoringMetricsServer(t *testing.T) {
	ctx := context.Background()
	clusterMonitorings := f.OpenShiftConfigClient.ConfigV1alpha1().ClusterMonitorings()

	_, err := clusterMonitorings.List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		if apierrors.IsNotFound(err) {
			t.Skip("ClusterMonitoring CRD not available - ClusterMonitoringConfig feature gate may not be enabled")
			return
		}
		t.Fatalf("unexpected error checking ClusterMonitoring CRD availability: %v", err)
	}

	t.Log("creating ClusterMonitoring resource with MetricsServerConfig")
	cm := &configv1alpha1.ClusterMonitoring{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterMonitoringName,
		},
		Spec: configv1alpha1.ClusterMonitoringSpec{
			MetricsServerConfig: configv1alpha1.MetricsServerConfig{
				Verbosity: configv1alpha1.VerbosityLevelInfo,
				Resources: []configv1alpha1.ContainerResource{
					{
						Name:    "cpu",
						Request: resource.MustParse("10m"),
						Limit:   resource.MustParse("100m"),
					},
					{
						Name:    "memory",
						Request: resource.MustParse("100Mi"),
						Limit:   resource.MustParse("200Mi"),
					},
				},
				NodeSelector: map[string]string{
					"kubernetes.io/os": "linux",
				},
			},
		},
	}

	f.MustCreateOrUpdateClusterMonitoring(t, cm)
	t.Cleanup(func() {
		// Reset to default verbosity (cannot set to completely empty spec)
		cm.Spec.MetricsServerConfig = configv1alpha1.MetricsServerConfig{
			Verbosity: configv1alpha1.VerbosityLevelErrors,
		}
		f.MustCreateOrUpdateClusterMonitoring(t, cm)
	})

	t.Logf("configured ClusterMonitoring resource: %s", cm.Name)

	for _, test := range []struct {
		name      string
		assertion func(*testing.T)
	}{
		{
			name:      "assert metrics-server deployment exists and rolled out",
			assertion: f.AssertDeploymentExistsAndRollout("metrics-server", f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/name=metrics-server,app.kubernetes.io/component=metrics-server",
				[]framework.PodAssertion{
					expectContainerArg("--v=2", "metrics-server"),
					expectMatchingRequests("*", "metrics-server", "100Mi", "10m"),
					expectMatchingLimits("*", "metrics-server", "200Mi", "100m"),
					expectNodeSelector("kubernetes.io/os", "linux"),
				},
			),
		},
	} {
		t.Run(test.name, test.assertion)
	}
}

func TestClusterMonitorMetricsServerConfigMapAndCRD(t *testing.T) {
	ctx := context.Background()

	// Verify CRD is available
	clusterMonitorings := f.OpenShiftConfigClient.ConfigV1alpha1().ClusterMonitorings()
	_, err := clusterMonitorings.List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		if apierrors.IsNotFound(err) {
			t.Skip("ClusterMonitoring CRD not available - ClusterMonitoringConfig feature gate may not be enabled")
			return
		}
		t.Fatalf("unexpected error checking ClusterMonitoring CRD availability: %v", err)
	}

	// Setup ConfigMap with baseline configuration
	t.Log("creating ConfigMap with baseline metrics-server configuration")
	configMapData := `metricsServer:
  nodeSelector:
    test-precedence: "from-configmap"
  resources:
    requests:
      cpu: "5m"
      memory: "50Mi"
`
	cm := f.BuildCMOConfigMap(t, configMapData)
	f.MustCreateOrUpdateConfigMap(t, cm)
	t.Cleanup(func() {
		f.MustDeleteConfigMap(t, cm)
	})

	// Create CRD with configuration that should override ConfigMap
	t.Log("creating ClusterMonitoring CRD with configuration that should override ConfigMap")
	crd := &configv1alpha1.ClusterMonitoring{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterMonitoringName,
		},
		Spec: configv1alpha1.ClusterMonitoringSpec{
			MetricsServerConfig: configv1alpha1.MetricsServerConfig{
				Verbosity: configv1alpha1.VerbosityLevelInfo,
				NodeSelector: map[string]string{
					"test-precedence": "from-crd", // Should override ConfigMap value
				},
				Resources: []configv1alpha1.ContainerResource{
					{
						Name:    "cpu",
						Request: resource.MustParse("10m"),  // Should override ConfigMap value
						Limit:   resource.MustParse("100m"), // Limit is required when request is set
					},
					{
						Name:    "memory",
						Request: resource.MustParse("100Mi"), // Should override ConfigMap value
						Limit:   resource.MustParse("200Mi"), // Limit is required when request is set
					},
				},
			},
		},
	}

	f.MustCreateOrUpdateClusterMonitoring(t, crd)
	t.Cleanup(func() {
		// Reset to default
		crd.Spec.MetricsServerConfig = configv1alpha1.MetricsServerConfig{
			Verbosity: configv1alpha1.VerbosityLevelErrors,
		}
		f.MustCreateOrUpdateClusterMonitoring(t, crd)
	})

	t.Logf("configured both ConfigMap and ClusterMonitoring CRD for precedence testing")

	for _, tc := range []scenario{
		{
			name:      "assert metrics-server deployment exists and rolled out",
			assertion: f.AssertDeploymentExistsAndRollout("metrics-server", f.Ns),
		},
		{
			name: "assert CRD configuration overrides ConfigMap configuration",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/name=metrics-server,app.kubernetes.io/component=metrics-server",
				[]framework.PodAssertion{
					// Verify that values from CRD take precedence over ConfigMap values
					expectContainerArg("--v=2", "metrics-server"),
					expectMatchingRequests("*", "metrics-server", "100Mi", "10m"),
					expectMatchingLimits("*", "metrics-server", "200Mi", "100m"),
					expectNodeSelector("test-precedence", "from-crd"),
				},
			),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

func expectMatchingLimits(podName, containerName, expectMem, expectCPU string) framework.PodAssertion {
	return func(pod v1.Pod) error {
		if podName == "*" || pod.Name == podName {
			for _, container := range pod.Spec.Containers {
				if container.Name == containerName {
					containerMemory := container.Resources.Limits[v1.ResourceMemory]
					actualMemory := containerMemory.String()
					if actualMemory != expectMem {
						return fmt.Errorf("memory limits %s does not match actual %s", expectMem, actualMemory)
					}
					containerCPU := container.Resources.Limits[v1.ResourceCPU]
					actualCPU := containerCPU.String()
					if actualCPU != expectCPU {
						return fmt.Errorf("CPU limits %s does not match actual %s", expectCPU, actualCPU)
					}
				}
			}
		}
		return nil
	}
}

func expectNodeSelector(key, value string) framework.PodAssertion {
	return func(pod v1.Pod) error {
		if pod.Spec.NodeSelector[key] != value {
			return fmt.Errorf("expected node selector %s=%s, got: %v", key, value, pod.Spec.NodeSelector)
		}
		return nil
	}
}
