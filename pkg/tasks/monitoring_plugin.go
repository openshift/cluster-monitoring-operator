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

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
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
	{ // plugin
		plg, err := t.factory.MonitoringPlugin()
		if err != nil {
			return errors.Wrap(err, "initializing Console Plugin failed")
		}

		if err := t.client.CreateOrUpdateConsolePlugin(ctx, plg); err != nil {
			return errors.Wrap(err, "reconciling Console Plugin failed")
		}

		if err = t.client.RegisterConsolePlugin(ctx, plg.Name); err != nil {
			return errors.Wrap(err, "registering Console Plugin failed")
		}
	}

	{ // config map
		cm, err := t.factory.MonitoringPluginConfigMap()
		if err != nil {
			return errors.Wrap(err, "initializing Console Plugin ConfigMap failed")
		}

		if err = t.client.CreateOrUpdateConfigMap(ctx, cm); err != nil {
			return errors.Wrap(err, "reconciling Console Plugin ConfigMap failed")
		}
	}

	{ // service acccount
		sa, err := t.factory.MonitoringPluginServiceAccount()
		if err != nil {
			return errors.Wrap(err, "initializing Console Plugin ServiceAccount failed")
		}

		err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
		if err != nil {
			return errors.Wrap(err, "reconciling Console Plugin ServiceAccount failed")
		}
	}

	{ // service
		svc, err := t.factory.MonitoringPluginService()
		if err != nil {
			return errors.Wrap(err, "initializing Console Plugin Service failed")
		}

		if err = t.client.CreateOrUpdateService(ctx, svc); err != nil {
			return errors.Wrap(err, "reconciling Console Plugin Service failed")
		}
	}

	{ // deployment
		d, err := t.factory.MonitoringPluginDeployment()
		if err != nil {
			return errors.Wrap(err, "initializing Console Plugin Deployment failed")
		}

		if err = t.client.CreateOrUpdateDeployment(ctx, d); err != nil {
			return errors.Wrap(err, "reconciling Console Plugin Deployment failed")
		}
	}

	{ // pod disruption budget
		pdb, err := t.factory.MonitoringPluginPodDisruptionBudget()
		if err != nil {
			return errors.Wrap(err, "initializing Console Plugin PDB failed")
		}

		if pdb != nil {
			if err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb); err != nil {
				return errors.Wrap(err, "reconciling Console Plugin PDB failed")
			}
		}
	}

	return nil
}
