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
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	clusterMonitoringName = "cluster"
)

func TestClusterMonitoring(t *testing.T) {
	ctx := context.Background()
	clusterMonitorings := f.OpenShiftConfigClient.ConfigV1alpha1().ClusterMonitorings()

	// Check if the ClusterMonitoring CRD is available (feature gate enabled)
	_, err := clusterMonitorings.List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		if apierrors.IsNotFound(err) {
			t.Skip("ClusterMonitoring CRD not available - ClusterMonitoringConfig feature gate may not be enabled")
			return
		}
		t.Fatalf("unexpected error checking ClusterMonitoring CRD availability: %v", err)
	}

	// Clean up any existing test resource first
	_ = clusterMonitorings.Delete(ctx, clusterMonitoringName, metav1.DeleteOptions{})

	time.Sleep(2 * time.Second)

	cm := &configv1alpha1.ClusterMonitoring{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterMonitoringName,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Spec: configv1alpha1.ClusterMonitoringSpec{
			AlertmanagerConfig: configv1alpha1.AlertmanagerConfig{
				DeploymentMode: configv1alpha1.AlertManagerDeployModeDefaultConfig,
			},
		},
	}

	t.Log("Creating ClusterMonitoring resource...")
	createdCM, err := clusterMonitorings.Create(ctx, cm, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create ClusterMonitoring: %v", err)
	}

	defer func() {
		t.Log("Cleaning up ClusterMonitoring resource...")
		err := clusterMonitorings.Delete(ctx, clusterMonitoringName, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("Failed to delete ClusterMonitoring: %v", err)
		}
	}()

	t.Logf("✅ Successfully created ClusterMonitoring resource: %s", createdCM.Name)

	err = wait.PollImmediate(5*time.Second, 30*time.Second, func() (bool, error) {
		retrievedCM, err := clusterMonitorings.Get(ctx, clusterMonitoringName, metav1.GetOptions{})
		if err != nil {
			t.Logf("Waiting for ClusterMonitoring to be available: %v", err)
			return false, nil
		}

		if retrievedCM.Spec.AlertmanagerConfig.DeploymentMode != configv1alpha1.AlertManagerDeployModeDefaultConfig {
			t.Logf("Waiting for correct AlertmanagerConfig.DeploymentMode, got: %s", retrievedCM.Spec.AlertmanagerConfig.DeploymentMode)
			return false, nil
		}

		t.Logf("✅ ClusterMonitoring resource retrieved successfully with correct spec")
		return true, nil
	})

	if err != nil {
		t.Fatalf("ClusterMonitoring resource was not properly created or retrieved: %v", err)
	}

	t.Log("Testing ClusterMonitoring resource update...")
	err = wait.PollImmediate(2*time.Second, 30*time.Second, func() (bool, error) {
		currentCM, err := clusterMonitorings.Get(ctx, clusterMonitoringName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		currentCM.Spec.AlertmanagerConfig.DeploymentMode = configv1alpha1.AlertManagerDeployModeCustomConfig
		currentCM.Spec.AlertmanagerConfig.CustomConfig = configv1alpha1.AlertmanagerCustomConfig{
			LogLevel: configv1alpha1.LogLevelInfo,
		}

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

	if updatedCM.Spec.AlertmanagerConfig.DeploymentMode != configv1alpha1.AlertManagerDeployModeCustomConfig {
		t.Errorf("Expected DeploymentMode to be CustomConfig, got: %s", updatedCM.Spec.AlertmanagerConfig.DeploymentMode)
	}

	if updatedCM.Spec.AlertmanagerConfig.CustomConfig.LogLevel != configv1alpha1.LogLevelInfo {
		t.Errorf("Expected LogLevel to be Info, got: %s", updatedCM.Spec.AlertmanagerConfig.CustomConfig.LogLevel)
	}

	t.Log("✅ ClusterMonitoring resource updated successfully")

	// TODO: Once the controller is integrated into the operator
	// - Controller processes the ClusterMonitoring resource
	// - Appropriate Alertmanager resources are created/updated/deleted
	// - Controller logs show the resource was processed
	// For now, this test verifies the CRD CRUD operations

	t.Log("✅ ClusterMonitoring e2e test completed successfully")
}
