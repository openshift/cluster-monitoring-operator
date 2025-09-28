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
