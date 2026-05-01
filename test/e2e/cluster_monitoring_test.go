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
	"time"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const clusterMonitoringName = "cluster"

// TestClusterMonitoringUserDefined tests UserDefinedMonitoring (enable/disable user workload monitoring via CRD).
func TestClusterMonitoringUserDefined(t *testing.T) {
	if !clusterMonitoringCRDAvailable {
		t.Skip("ClusterMonitoring CRD not available (TechPreview / ClusterMonitoringConfig feature gate may be disabled)")
		return
	}
	ctx := context.Background()
	clusterMonitorings := f.OpenShiftConfigClient.ConfigV1alpha1().ClusterMonitorings()

	// ConfigMap with no enableUserWorkload so the CRD is the source of truth for this test.
	t.Log("setting cluster-monitoring-config with no enableUserWorkload (CRD will drive UWM state)")
	cmoConfigMap := f.BuildCMOConfigMap(t, "{}")
	f.MustCreateOrUpdateConfigMap(t, cmoConfigMap)
	t.Cleanup(func() {
		f.MustCreateOrUpdateConfigMap(t, cmoConfigMap)
	})

	t.Log("creating ClusterMonitoring resource with UserDefined disabled")
	cm := &configv1alpha1.ClusterMonitoring{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterMonitoringName,
		},
		Spec: configv1alpha1.ClusterMonitoringSpec{
			UserDefined: configv1alpha1.UserDefinedMonitoring{
				Mode: configv1alpha1.UserDefinedDisabled,
			},
		},
	}

	f.MustCreateOrUpdateClusterMonitoring(t, cm)
	t.Cleanup(func() {
		cm.Spec.UserDefined.Mode = configv1alpha1.UserDefinedDisabled
		f.MustCreateOrUpdateClusterMonitoring(t, cm)
	})

	t.Logf("configured ClusterMonitoring resource: %s", cm.Name)

	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, 30*time.Second, true, func(context.Context) (bool, error) {
		retrievedCM, err := clusterMonitorings.Get(ctx, clusterMonitoringName, metav1.GetOptions{})
		if err != nil {
			t.Logf("waiting for ClusterMonitoring: %v", err)
			return false, nil
		}

		if retrievedCM.Spec.UserDefined.Mode != configv1alpha1.UserDefinedDisabled {
			t.Logf("waiting for correct UserDefined mode, got: %s", retrievedCM.Spec.UserDefined.Mode)
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		t.Fatalf("ClusterMonitoring resource not properly created: %v", err)
	}

	t.Log("verifying user workload monitoring is disabled")
	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 3*time.Minute, true, func(context.Context) (bool, error) {
		_, err := f.KubeClient.AppsV1().StatefulSets(f.UserWorkloadMonitoringNs).Get(ctx, "prometheus-user-workload", metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				t.Log("prometheus-user-workload not found (expected when disabled)")
				return true, nil
			}
			t.Logf("error checking prometheus-user-workload: %v", err)
			return false, nil
		}
		t.Log("prometheus-user-workload still exists, waiting for it to be removed")
		return false, nil
	})

	if err != nil {
		t.Fatalf("user workload monitoring not properly disabled: %v", err)
	}

	t.Log("updating ClusterMonitoring to enable UserDefined monitoring")
	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 30*time.Second, true, func(context.Context) (bool, error) {
		currentCM, err := clusterMonitorings.Get(ctx, clusterMonitoringName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		currentCM.Spec.UserDefined.Mode = configv1alpha1.UserDefinedNamespaceIsolated

		_, err = clusterMonitorings.Update(ctx, currentCM, metav1.UpdateOptions{})
		if err != nil {
			t.Logf("Retrying update due to: %v", err)
			return false, nil
		}

		return true, nil
	})

	if err != nil {
		t.Fatalf("Failed to update ClusterMonitoring: %v", err)
	}

	updatedCM, err := clusterMonitorings.Get(ctx, clusterMonitoringName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get updated ClusterMonitoring: %v", err)
	}

	if updatedCM.Spec.UserDefined.Mode != configv1alpha1.UserDefinedNamespaceIsolated {
		t.Errorf("Expected UserDefined mode to be NamespaceIsolated, got: %s", updatedCM.Spec.UserDefined.Mode)
	}

	t.Log("verifying user workload monitoring is enabled")
	err = wait.PollUntilContextTimeout(ctx, 10*time.Second, 5*time.Minute, true, func(context.Context) (bool, error) {
		_, err := f.KubeClient.AppsV1().StatefulSets(f.UserWorkloadMonitoringNs).Get(ctx, "prometheus-user-workload", metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("prometheus-user-workload did not appear after enabling UserDefined=NamespaceIsolated via ClusterMonitoring CRD: %v", err)
	}
	f.AssertStatefulSetExistsAndRolloutFunc("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)
}

// TestConfigMapEnableUserWorkloadOverridesCRD verifies that when enableUserWorkload is set in the
// cluster-monitoring-config ConfigMap, that value is used and the ClusterMonitoring CRD is ignored.
func TestConfigMapEnableUserWorkloadOverridesCRD(t *testing.T) {
	if !clusterMonitoringCRDAvailable {
		t.Skip("ClusterMonitoring CRD not available (TechPreview / ClusterMonitoringConfig feature gate may be disabled)")
		return
	}
	ctx := context.Background()

	t.Log("CRD UserDefined=Disabled, ConfigMap enableUserWorkload=true → ConfigMap wins, UWM enabled")
	cmCR := &configv1alpha1.ClusterMonitoring{
		ObjectMeta: metav1.ObjectMeta{Name: clusterMonitoringName},
		Spec: configv1alpha1.ClusterMonitoringSpec{
			UserDefined: configv1alpha1.UserDefinedMonitoring{Mode: configv1alpha1.UserDefinedDisabled},
		},
	}
	f.MustCreateOrUpdateClusterMonitoring(t, cmCR)
	t.Cleanup(func() {
		cmCR.Spec.UserDefined.Mode = configv1alpha1.UserDefinedDisabled
		f.MustCreateOrUpdateClusterMonitoring(t, cmCR)
	})

	// Establish disabled baseline before asserting ConfigMap override.
	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, "{}"))
	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, 3*time.Minute, true, func(context.Context) (bool, error) {
		_, getErr := f.KubeClient.AppsV1().StatefulSets(f.UserWorkloadMonitoringNs).Get(ctx, "prometheus-user-workload", metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			return true, nil
		}
		if getErr != nil {
			return false, getErr
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("failed to establish disabled baseline: prometheus-user-workload still present: %v", err)
	}

	cmoConfigMap := f.BuildCMOConfigMap(t, "enableUserWorkload: true")
	f.MustCreateOrUpdateConfigMap(t, cmoConfigMap)
	t.Cleanup(func() {
		f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, "{}"))
	})

	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 5*time.Minute, true, func(context.Context) (bool, error) {
		_, getErr := f.KubeClient.AppsV1().StatefulSets(f.UserWorkloadMonitoringNs).Get(ctx, "prometheus-user-workload", metav1.GetOptions{})
		if getErr != nil {
			if apierrors.IsNotFound(getErr) {
				return false, nil
			}
			t.Logf("error checking prometheus-user-workload: %v", getErr)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("when enableUserWorkload is set in ConfigMap it must be used and CRD ignored; expected UWM enabled: %v", err)
	}
	t.Log("PASS: ConfigMap enableUserWorkload was used, CRD was ignored; UWM is enabled.")
}

// TestClusterMonitoringMetricsServer tests MetricsServerConfig via ClusterMonitoring CRD.
func TestClusterMonitoringMetricsServer(t *testing.T) {
	if !clusterMonitoringCRDAvailable {
		t.Skip("ClusterMonitoring CRD not available (TechPreview / ClusterMonitoringConfig feature gate may be disabled)")
		return
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
		cm.Spec.MetricsServerConfig = configv1alpha1.MetricsServerConfig{
			Verbosity: configv1alpha1.VerbosityLevelErrors,
		}
		f.MustCreateOrUpdateClusterMonitoring(t, cm)
	})

	t.Logf("configured ClusterMonitoring resource: %s", cm.Name)

	for _, test := range []scenario{
		{
			name:      "assert metrics-server deployment exists and rolled out",
			assertion: f.AssertDeploymentExistsAndRolloutFunc("metrics-server", f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfigurationFunc(
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

// TestClusterMonitorMetricsServerConfigMapAndCRD verifies Phase 1 merge: when both ConfigMap and CR
// specify metricsServer, the ConfigMap wins at the top level and CR values are ignored.
func TestClusterMonitorMetricsServerConfigMapAndCRD(t *testing.T) {
	if !clusterMonitoringCRDAvailable {
		t.Skip("ClusterMonitoring CRD not available (TechPreview / ClusterMonitoringConfig feature gate may be disabled)")
		return
	}

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

	t.Log("creating ClusterMonitoring CR with different metricsServer settings (must be ignored when ConfigMap defines metricsServer)")
	crd := &configv1alpha1.ClusterMonitoring{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterMonitoringName,
		},
		Spec: configv1alpha1.ClusterMonitoringSpec{
			MetricsServerConfig: configv1alpha1.MetricsServerConfig{
				Verbosity: configv1alpha1.VerbosityLevelInfo,
				NodeSelector: map[string]string{
					"test-precedence": "from-crd",
				},
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
			},
		},
	}

	f.MustCreateOrUpdateClusterMonitoring(t, crd)
	t.Cleanup(func() {
		crd.Spec.MetricsServerConfig = configv1alpha1.MetricsServerConfig{
			Verbosity: configv1alpha1.VerbosityLevelErrors,
		}
		f.MustCreateOrUpdateClusterMonitoring(t, crd)
	})

	t.Logf("configured both ConfigMap and ClusterMonitoring CR for Phase 1 precedence (ConfigMap wins)")

	for _, tc := range []scenario{
		{
			name:      "assert metrics-server deployment exists and rolled out",
			assertion: f.AssertDeploymentExistsAndRolloutFunc("metrics-server", f.Ns),
		},
		{
			name: "assert ConfigMap metricsServer is used; CR metricsServer is ignored",
			assertion: f.AssertPodConfigurationFunc(
				f.Ns,
				"app.kubernetes.io/name=metrics-server,app.kubernetes.io/component=metrics-server",
				[]framework.PodAssertion{
					expectMatchingRequests("*", "metrics-server", "50Mi", "5m"),
					expectNodeSelector("test-precedence", "from-configmap"),
				},
			),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

// TestClusterMonitoringAlertmanager tests alertmanagerConfig via ClusterMonitoring CRD (CustomConfig).
func TestClusterMonitoringAlertmanager(t *testing.T) {
	if !clusterMonitoringCRDAvailable {
		t.Skip("ClusterMonitoring CRD not available (TechPreview / ClusterMonitoringConfig feature gate may be disabled)")
		return
	}

	t.Log("creating ClusterMonitoring resource with alertmanagerConfig CustomConfig")
	cm := &configv1alpha1.ClusterMonitoring{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterMonitoringName,
		},
		Spec: configv1alpha1.ClusterMonitoringSpec{
			AlertmanagerConfig: configv1alpha1.AlertmanagerConfig{
				DeploymentMode: configv1alpha1.AlertManagerDeployModeCustomConfig,
				CustomConfig: configv1alpha1.AlertmanagerCustomConfig{
					LogLevel: configv1alpha1.LogLevelDebug,
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
		},
	}

	f.MustCreateOrUpdateClusterMonitoring(t, cm)
	t.Cleanup(func() {
		cm.Spec.AlertmanagerConfig = configv1alpha1.AlertmanagerConfig{
			DeploymentMode: configv1alpha1.AlertManagerDeployModeDefaultConfig,
		}
		f.MustCreateOrUpdateClusterMonitoring(t, cm)
	})

	t.Logf("configured ClusterMonitoring resource: %s", cm.Name)

	for _, test := range []scenario{
		{
			name:      "assert alertmanager-main statefulset exists and rolled out",
			assertion: f.AssertStatefulSetExistsAndRolloutFunc("alertmanager-main", f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfigurationFunc(
				f.Ns,
				"app.kubernetes.io/name=alertmanager,app.kubernetes.io/instance=main",
				[]framework.PodAssertion{
					expectMatchingRequests("*", "alertmanager", "100Mi", "10m"),
					expectMatchingLimits("*", "alertmanager", "200Mi", "100m"),
					expectNodeSelector("kubernetes.io/os", "linux"),
				},
			),
		},
	} {
		t.Run(test.name, test.assertion)
	}
}

// TestClusterMonitorAlertmanagerConfigMapAndCRD verifies Phase 1 merge: when both ConfigMap and CR
// specify alertmanagerMain / alertmanagerConfig, the ConfigMap wins at the top level and CR values are ignored.
func TestClusterMonitorAlertmanagerConfigMapAndCRD(t *testing.T) {
	if !clusterMonitoringCRDAvailable {
		t.Skip("ClusterMonitoring CRD not available (TechPreview / ClusterMonitoringConfig feature gate may be disabled)")
		return
	}

	t.Log("creating ConfigMap with baseline alertmanagerMain configuration")
	configMapData := `alertmanagerMain:
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

	t.Log("creating ClusterMonitoring CR with different alertmanager settings (must be ignored when ConfigMap defines alertmanagerMain)")
	crd := &configv1alpha1.ClusterMonitoring{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterMonitoringName,
		},
		Spec: configv1alpha1.ClusterMonitoringSpec{
			AlertmanagerConfig: configv1alpha1.AlertmanagerConfig{
				DeploymentMode: configv1alpha1.AlertManagerDeployModeCustomConfig,
				CustomConfig: configv1alpha1.AlertmanagerCustomConfig{
					NodeSelector: map[string]string{
						"test-precedence": "from-crd",
					},
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
				},
			},
		},
	}

	f.MustCreateOrUpdateClusterMonitoring(t, crd)
	t.Cleanup(func() {
		crd.Spec.AlertmanagerConfig = configv1alpha1.AlertmanagerConfig{
			DeploymentMode: configv1alpha1.AlertManagerDeployModeDefaultConfig,
		}
		f.MustCreateOrUpdateClusterMonitoring(t, crd)
	})

	t.Logf("configured both ConfigMap and ClusterMonitoring CR for Phase 1 precedence (ConfigMap wins)")

	for _, tc := range []scenario{
		{
			name:      "assert alertmanager-main statefulset exists and rolled out",
			assertion: f.AssertStatefulSetExistsAndRolloutFunc("alertmanager-main", f.Ns),
		},
		{
			name: "assert ConfigMap alertmanagerMain is used; CR alertmanagerConfig is ignored",
			assertion: f.AssertPodConfigurationFunc(
				f.Ns,
				"app.kubernetes.io/name=alertmanager,app.kubernetes.io/instance=main",
				[]framework.PodAssertion{
					expectMatchingRequests("*", "alertmanager", "50Mi", "5m"),
					expectNodeSelector("test-precedence", "from-configmap"),
				},
			),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

func expectMatchingLimits(podName, containerName, expectMem, expectCPU string) framework.PodAssertion {
	return func(pod v1.Pod) error {
		if podName != "*" && pod.Name != podName {
			return nil
		}
		var found bool
		for _, container := range pod.Spec.Containers {
			if container.Name == containerName {
				found = true
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
				break
			}
		}
		if !found {
			return fmt.Errorf("container %q not found in pod %s (containers: %v)", containerName, pod.Name, containerNames(pod.Spec.Containers))
		}
		return nil
	}
}

func containerNames(containers []v1.Container) []string {
	names := make([]string, 0, len(containers))
	for _, c := range containers {
		names = append(names, c.Name)
	}
	return names
}

func expectNodeSelector(key, value string) framework.PodAssertion {
	return func(pod v1.Pod) error {
		if pod.Spec.NodeSelector[key] != value {
			return fmt.Errorf("expected node selector %s=%s, got: %v", key, value, pod.Spec.NodeSelector)
		}
		return nil
	}
}
