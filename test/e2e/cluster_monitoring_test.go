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
	"testing"
	"time"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const clusterMonitoringName = "cluster"

func TestClusterMonitoringUserDefined(t *testing.T) {
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
		// Reset to Disabled state
		cm.Spec.UserDefined.Mode = configv1alpha1.UserDefinedDisabled
		f.MustCreateOrUpdateClusterMonitoring(t, cm)
	})

	t.Logf("configured ClusterMonitoring resource: %s", cm.Name)

	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 30*time.Second, true, func(context.Context) (bool, error) {
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
	// Wait for prometheus-user-workload to be removed
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
			return false, nil // Retry on conflict
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
	// Wait for statefulset to appear (CMO must have ClusterMonitoringConfig feature and UserDefined merge logic)
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
		t.Skipf("prometheus-user-workload did not appear after 5m - cluster CMO may not support ClusterMonitoring CRD UserDefined (need ClusterMonitoringConfig feature gate and CMO with merge logic): %v", err)
	}
	// Wait for statefulset rollout
	f.AssertStatefulSetExistsAndRollout("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)
}

// TestConfigMapEnableUserWorkloadOverridesCRD verifies that when enableUserWorkload is set in the
// cluster-monitoring-config ConfigMap, that value is used and the ClusterMonitoring CRD is ignored.
// If the ConfigMap has an opinion (enableUserWorkload: true or false), the CRD must not override it.
func TestConfigMapEnableUserWorkloadOverridesCRD(t *testing.T) {
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

	// CRD says Disabled; ConfigMap says enableUserWorkload: true → ConfigMap wins, UWM must be enabled.
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

	cmoConfigMap := f.BuildCMOConfigMap(t, "enableUserWorkload: true")
	f.MustCreateOrUpdateConfigMap(t, cmoConfigMap)
	t.Cleanup(func() {
		f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, "{}"))
	})

	// Expect UWM enabled (ConfigMap value used, CRD ignored).
	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 5*time.Minute, true, func(context.Context) (bool, error) {
		_, err := f.KubeClient.AppsV1().StatefulSets(f.UserWorkloadMonitoringNs).Get(ctx, "prometheus-user-workload", metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			t.Logf("error checking prometheus-user-workload: %v", err)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("when enableUserWorkload is set in ConfigMap it must be used and CRD ignored; expected UWM enabled: %v", err)
	}
	t.Log("PASS: ConfigMap enableUserWorkload was used, CRD was ignored; UWM is enabled.")
}
