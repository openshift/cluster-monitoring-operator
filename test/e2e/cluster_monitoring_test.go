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

const (
	clusterMonitoringName = "cluster"
)

func TestClusterMonitoring(t *testing.T) {
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

	cm := &configv1alpha1.ClusterMonitoring{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterMonitoringName,
		},
		Spec: configv1alpha1.ClusterMonitoringSpec{
			AlertmanagerConfig: configv1alpha1.AlertmanagerConfig{
				DeploymentMode: configv1alpha1.AlertManagerDeployModeDefaultConfig,
			},
		},
	}

	createdCM, err := clusterMonitorings.Create(ctx, cm, metav1.CreateOptions{})
	if err != nil {
		if !apierrors.IsAlreadyExists(err) {
			t.Fatalf("failed to create ClusterMonitoring: %v", err)
		}
		existingCM, err := clusterMonitorings.Get(ctx, clusterMonitoringName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("failed to get existing ClusterMonitoring: %v", err)
		}
		existingCM.Spec = cm.Spec
		createdCM, err = clusterMonitorings.Update(ctx, existingCM, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("failed to update ClusterMonitoring: %v", err)
		}
	}

	t.Logf("configured ClusterMonitoring resource: %s", createdCM.Name)

	err = wait.PollImmediate(5*time.Second, 30*time.Second, func() (bool, error) {
		retrievedCM, err := clusterMonitorings.Get(ctx, clusterMonitoringName, metav1.GetOptions{})
		if err != nil {
			t.Logf("waiting for ClusterMonitoring: %v", err)
			return false, nil
		}

		if retrievedCM.Spec.AlertmanagerConfig.DeploymentMode != configv1alpha1.AlertManagerDeployModeDefaultConfig {
			t.Logf("waiting for correct DeploymentMode, got: %s", retrievedCM.Spec.AlertmanagerConfig.DeploymentMode)
			return false, nil
		}

		return true, nil
	})

	if err != nil {
		t.Fatalf("ClusterMonitoring resource not properly created: %v", err)
	}

	t.Log("updating ClusterMonitoring resource")
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
		t.Errorf("expected LogLevel Info, got: %s", updatedCM.Spec.AlertmanagerConfig.CustomConfig.LogLevel)
	}

	t.Log("verifying alertmanager deployment reflects CRD configuration")
	err = wait.PollImmediate(5*time.Second, 2*time.Minute, func() (bool, error) {
		am, err := f.MonitoringClient.Alertmanagers(f.Ns).Get(ctx, "main", metav1.GetOptions{})
		if err != nil {
			t.Logf("waiting for alertmanager: %v", err)
			return false, nil
		}

		if am.Status.UpdatedReplicas < 1 {
			t.Logf("waiting for alertmanager replicas, current: %d", am.Status.UpdatedReplicas)
			return false, nil
		}

		if am.Spec.LogLevel != "info" {
			t.Logf("unexpected log level: %s", am.Spec.LogLevel)
		}

		return true, nil
	})

	if err != nil {
		t.Fatalf("alertmanager not properly configured from CRD: %v", err)
	}
}
