// Copyright 2018 The Cluster Monitoring Operator Authors
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

// TODO this file can be be removed in 4.12
import (
	"context"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
)

type GrafanaTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewGrafanaTask(client *client.Client, factory *manifests.Factory, config *manifests.Config) *GrafanaTask {
	return &GrafanaTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *GrafanaTask) Run(ctx context.Context) client.StateErrors {
	return stateErrors(t.cleanup(ctx))
}

func (t *GrafanaTask) cleanup(ctx context.Context) error {
	sm, err := t.factory.GrafanaServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Grafana ServiceMonitor failed")
	}

	err = t.client.DeleteServiceMonitor(ctx, sm)
	if err != nil {
		return errors.Wrap(err, "deleting Grafana ServiceMonitor failed")
	}

	{
		trustedCA, err := t.factory.GrafanaTrustedCABundle()
		if err != nil {
			return errors.Wrap(err, "initializing Grafana CA bundle ConfigMap failed")
		}

		d, err := t.factory.GrafanaDeployment(trustedCA)
		if err != nil {
			return errors.Wrap(err, "initializing Grafana Deployment failed")
		}

		err = t.client.DeleteDeployment(ctx, d)
		if err != nil {
			return errors.Wrap(err, "deleting Grafana Deployment failed")
		}

		err = t.client.DeleteConfigMap(ctx, trustedCA)
		if err != nil {
			return errors.Wrap(err, "deleting Grafana CA bundle ConfigMap failed")
		}

		err = t.client.DeleteHashedConfigMap(ctx, t.client.Namespace(), "grafana", "")
		if err != nil {
			return errors.Wrap(err, "deleting hashed Grafana CA bundle ConfigMap failed")
		}
	}

	svc, err := t.factory.GrafanaService()
	if err != nil {
		return errors.Wrap(err, "initializing Grafana Service failed")
	}

	err = t.client.DeleteService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "deleting Grafana Service failed")
	}

	sa, err := t.factory.GrafanaServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Grafana ServiceAccount failed")
	}

	err = t.client.DeleteServiceAccount(ctx, sa)
	if err != nil {
		return errors.Wrap(err, "deleting Grafana ServiceAccount failed")
	}

	cmdbs, err := t.factory.GrafanaDashboardSources()
	if err != nil {
		return errors.Wrap(err, "initializing Grafana Dashboard Sources ConfigMap failed")
	}

	err = t.client.DeleteConfigMap(ctx, cmdbs)
	if err != nil {
		return errors.Wrap(err, "deleting Grafana Dashboard Sources ConfigMap failed")
	}

	cmdds, err := t.factory.GrafanaDashboardDefinitions()
	if err != nil {
		return errors.Wrap(err, "initializing Grafana Dashboard Definitions ConfigMaps failed")
	}

	err = t.client.DeleteConfigMapList(ctx, cmdds)
	if err != nil {
		return errors.Wrap(err, "deleting Grafana Dashboard Definitions ConfigMaps failed")
	}

	sds, err := t.factory.GrafanaDatasources()
	if err != nil {
		return errors.Wrap(err, "initializing Grafana Datasources Secret failed")
	}

	err = t.client.DeleteSecret(ctx, sds)
	if err != nil {
		return errors.Wrap(err, "deleting Grafana Datasources Secret failed")
	}

	smc, err := t.factory.GrafanaConfig()
	if err != nil {
		return errors.Wrap(err, "initializing Grafana Config Secret failed")
	}

	err = t.client.DeleteSecret(ctx, smc)
	if err != nil {
		return errors.Wrap(err, "deleting Grafana Config Secret failed")
	}

	rs, err := t.factory.GrafanaRBACProxyMetricSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Grafana RBAC proxy metric Secret failed")
	}

	err = t.client.DeleteSecret(ctx, rs)
	if err != nil {
		return errors.Wrap(err, "deleting Grafana RBAC proxy metric Secret failed")
	}

	ps, err := t.factory.GrafanaProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Grafana proxy Secret failed")
	}

	err = t.client.DeleteSecret(ctx, ps)
	if err != nil {
		return errors.Wrap(err, "deleting Grafana proxy Secret failed")
	}

	r, err := t.factory.GrafanaRoute()
	if err != nil {
		return errors.Wrap(err, "initializing Grafana Route failed")
	}

	err = t.client.DeleteRoute(ctx, r)
	if err != nil {
		return errors.Wrap(err, "deleting Grafana Route failed")
	}

	crb, err := t.factory.GrafanaClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Grafana ClusterRoleBinding failed")
	}

	err = t.client.DeleteClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "deleting Grafana ClusterRoleBinding failed")
	}

	cr, err := t.factory.GrafanaClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Grafana ClusterRole failed")
	}

	err = t.client.DeleteClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "delete Grafana ClusterRole failed")
	}

	return nil
}
