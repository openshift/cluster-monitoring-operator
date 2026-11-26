// Copyright 2023 The Cluster Monitoring Operator Authors
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

package tasks

import (
	"context"
	"fmt"
	"slices"

	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

type MonitoringPluginTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewMonitoringPluginTask(client *client.Client, factory *manifests.Factory, cfg *manifests.Config) *MonitoringPluginTask {
	return &MonitoringPluginTask{
		client:  client,
		factory: factory,
		config:  cfg,
	}
}

func (t *MonitoringPluginTask) Run(ctx context.Context) error {
	{
		netpol, err := t.factory.MonitoringPluginNetworkPolicy()
		if err != nil {
			return fmt.Errorf("initializing Console Plugin NetworkPolicy failed: %w", err)
		}

		err = t.client.CreateOrUpdateNetworkPolicy(ctx, netpol)
		if err != nil {
			return fmt.Errorf("reconciling Console Plugin NetworkPolicy failed: %w", err)
		}
	}

	// NOTE:  console capability (like other capabilities) can only go from
	// disabled -> enabled and not the other way around, meaning that CMO
	// doesn't have to deal with removal of the console plugin resources.
	// Hence, skip installing console if console capability is disabled.
	{
		enabled, err := t.client.HasConsoleCapability(ctx)
		if err != nil {
			return fmt.Errorf("failed to determine if console capability is enabled: %w", err)
		}

		if !enabled {
			klog.V(4).Infof("Skipping installation of Console Plugin as console capability is disabled")
			return nil
		}
	}

	{ // plugin
		plg, err := t.factory.MonitoringPlugin()
		if err != nil {
			return fmt.Errorf("initializing Console Plugin failed: %w", err)
		}

		if err := t.client.CreateOrUpdateConsolePlugin(ctx, plg); err != nil {
			return fmt.Errorf("reconciling Console Plugin failed: %w", err)
		}

		if err = t.client.RegisterConsolePlugin(ctx, plg.Name); err != nil {
			return fmt.Errorf("registering Console Plugin failed: %w", err)
		}
	}

	{ // service acccount
		sa, err := t.factory.MonitoringPluginServiceAccount()
		if err != nil {
			return fmt.Errorf("initializing Console Plugin ServiceAccount failed: %w", err)
		}

		err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
		if err != nil {
			return fmt.Errorf("reconciling Console Plugin ServiceAccount failed: %w", err)
		}
	}

	{ // role-based access control for the alerts management API
		if err := t.reconcileAlertsManagementRBAC(ctx); err != nil {
			return err
		}
	}

	{
		svc, err := t.factory.MonitoringPluginService()
		if err != nil {
			return fmt.Errorf("initializing Console Plugin Service failed: %w", err)
		}

		if err = t.client.CreateOrUpdateService(ctx, svc); err != nil {
			return fmt.Errorf("reconciling Console Plugin Service failed: %w", err)
		}

		d, err := t.factory.MonitoringPluginDeployment()
		if err != nil {
			return fmt.Errorf("initializing Console Plugin Deployment failed: %w", err)
		}

		if err = t.client.CreateOrUpdateDeployment(ctx, d); err != nil {
			return fmt.Errorf("reconciling Console Plugin Deployment failed: %w", err)
		}
	}

	{ // pod disruption budget
		pdb, err := t.factory.MonitoringPluginPodDisruptionBudget()
		if err != nil {
			return fmt.Errorf("initializing Console Plugin PDB failed: %w", err)
		}

		if pdb != nil {
			if err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb); err != nil {
				return fmt.Errorf("reconciling Console Plugin PDB failed: %w", err)
			}
		}
	}

	return nil
}

// alertsManagementAPIEnabled reports whether the alert-management-api
// feature is enabled for the monitoring plugin. The feature grants the
// plugin's service account the read-only RBAC it needs to serve the
// alerts management API.
func (t *MonitoringPluginTask) alertsManagementAPIEnabled() bool {
	pluginConfig := t.config.ClusterMonitoringConfiguration.MonitoringPluginConfig
	if pluginConfig == nil {
		return false
	}

	return slices.Contains(pluginConfig.Features, manifests.MonitoringPluginAlertManagementAPIFeature)
}

// userWorkloadMonitoringEnabled reports whether user workload monitoring
// is enabled. The user workload monitoring alertmanager and its route only
// exist when it is.
func (t *MonitoringPluginTask) userWorkloadMonitoringEnabled() bool {
	c := t.config.ClusterMonitoringConfiguration
	return c != nil && c.UserWorkloadEnabled != nil && *c.UserWorkloadEnabled
}

// reconcileAlertsManagementRBAC ensures that the plugin's service account
// holds the read-only permissions required by the alerts management API
// when the feature is enabled, and that they are removed otherwise.
func (t *MonitoringPluginTask) reconcileAlertsManagementRBAC(ctx context.Context) error {
	if err := t.reconcileAlertsManagementClusterRBAC(ctx); err != nil {
		return err
	}

	if err := t.reconcileAlertsManagementNamespacedRBAC(ctx); err != nil {
		return err
	}

	return t.reconcileAlertsManagementUserWorkloadRBAC(ctx)
}

func (t *MonitoringPluginTask) reconcileAlertsManagementClusterRBAC(ctx context.Context) error {
	cr, err := t.factory.MonitoringPluginClusterRole()
	if err != nil {
		return fmt.Errorf("initializing Console Plugin ClusterRole failed: %w", err)
	}

	crb, err := t.factory.MonitoringPluginClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Console Plugin ClusterRoleBinding failed: %w", err)
	}

	if t.alertsManagementAPIEnabled() {
		if err := t.client.CreateOrUpdateClusterRole(ctx, cr); err != nil {
			return fmt.Errorf("reconciling Console Plugin ClusterRole failed: %w", err)
		}

		if err := t.client.CreateOrUpdateClusterRoleBinding(ctx, crb); err != nil {
			return fmt.Errorf("reconciling Console Plugin ClusterRoleBinding failed: %w", err)
		}

		return nil
	}

	if err := t.client.DeleteClusterRole(ctx, cr); err != nil {
		return fmt.Errorf("deleting Console Plugin ClusterRole failed: %w", err)
	}

	if err := t.client.DeleteClusterRoleBinding(ctx, crb); err != nil {
		return fmt.Errorf("deleting Console Plugin ClusterRoleBinding failed: %w", err)
	}

	return nil
}

func (t *MonitoringPluginTask) reconcileAlertsManagementNamespacedRBAC(ctx context.Context) error {
	role, err := t.factory.MonitoringPluginRole()
	if err != nil {
		return fmt.Errorf("initializing Console Plugin Role failed: %w", err)
	}

	rb, err := t.factory.MonitoringPluginRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Console Plugin RoleBinding failed: %w", err)
	}

	if t.alertsManagementAPIEnabled() {
		if err := t.client.CreateOrUpdateRole(ctx, role); err != nil {
			return fmt.Errorf("reconciling Console Plugin Role failed: %w", err)
		}

		if err := t.client.CreateOrUpdateRoleBinding(ctx, rb); err != nil {
			return fmt.Errorf("reconciling Console Plugin RoleBinding failed: %w", err)
		}

		return nil
	}

	if err := t.client.DeleteRole(ctx, role); err != nil {
		return fmt.Errorf("deleting Console Plugin Role failed: %w", err)
	}

	if err := t.client.DeleteRoleBinding(ctx, rb); err != nil {
		return fmt.Errorf("deleting Console Plugin RoleBinding failed: %w", err)
	}

	return nil
}

func (t *MonitoringPluginTask) reconcileAlertsManagementUserWorkloadRBAC(ctx context.Context) error {
	role, err := t.factory.MonitoringPluginUserWorkloadRole()
	if err != nil {
		return fmt.Errorf("initializing Console Plugin user workload Role failed: %w", err)
	}

	rb, err := t.factory.MonitoringPluginUserWorkloadRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Console Plugin user workload RoleBinding failed: %w", err)
	}

	if t.alertsManagementAPIEnabled() && t.userWorkloadMonitoringEnabled() {
		if err := t.client.CreateOrUpdateRole(ctx, role); err != nil {
			return fmt.Errorf("reconciling Console Plugin user workload Role failed: %w", err)
		}

		if err := t.client.CreateOrUpdateRoleBinding(ctx, rb); err != nil {
			return fmt.Errorf("reconciling Console Plugin user workload RoleBinding failed: %w", err)
		}

		return nil
	}

	if err := t.client.DeleteRole(ctx, role); err != nil {
		return fmt.Errorf("deleting Console Plugin user workload Role failed: %w", err)
	}

	if err := t.client.DeleteRoleBinding(ctx, rb); err != nil {
		return fmt.Errorf("deleting Console Plugin user workload RoleBinding failed: %w", err)
	}

	return nil
}
