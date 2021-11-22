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

import (
	"context"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
)

type AlertmanagerTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewAlertmanagerTask(
	client *client.Client,
	factory *manifests.Factory,
	config *manifests.Config,
) *AlertmanagerTask {
	return &AlertmanagerTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *AlertmanagerTask) Run(ctx context.Context) error {
	if t.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.IsEnabled() {
		return t.create(ctx)
	}

	return t.destroy(ctx)
}

func (t *AlertmanagerTask) create(ctx context.Context) error {
	r, err := t.factory.AlertmanagerRoute()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager Route failed")
	}

	err = t.client.CreateRouteIfNotExists(ctx, r)
	if err != nil {
		return errors.Wrap(err, "creating Alertmanager Route failed")
	}

	host, err := t.client.WaitForRouteReady(ctx, r)
	if err != nil {
		return errors.Wrap(err, "waiting for Alertmanager Route to become ready failed")
	}

	s, err := t.factory.AlertmanagerConfig()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager configuration Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ctx, s)
	if err != nil {
		return errors.Wrap(err, "creating Alertmanager configuration Secret failed")
	}

	pdb, err := t.factory.AlertmanagerPodDisruptionBudget()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager PodDisruptionBudget object failed")
	}

	if pdb != nil {
		err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb)
		if err != nil {
			return errors.Wrap(err, "reconciling Alertmanager PodDisruptionBudget object failed")
		}
	}

	rs, err := t.factory.AlertmanagerRBACProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager RBAC proxy Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ctx, rs)
	if err != nil {
		return errors.Wrap(err, "creating Alertmanager RBAC proxy Secret failed")
	}

	rsm, err := t.factory.AlertmanagerRBACProxyMetricSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager RBAC proxy metric Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ctx, rsm)
	if err != nil {
		return errors.Wrap(err, "creating Alertmanager RBAC proxy metric Secret failed")
	}

	cr, err := t.factory.AlertmanagerClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "reconciling Alertmanager ClusterRole failed")
	}

	crb, err := t.factory.AlertmanagerClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "reconciling Alertmanager ClusterRoleBinding failed")
	}

	sa, err := t.factory.AlertmanagerServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager ServiceAccount failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return errors.Wrap(err, "reconciling Alertmanager ServiceAccount failed")
	}

	ps, err := t.factory.AlertmanagerProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager proxy Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ctx, ps)
	if err != nil {
		return errors.Wrap(err, "creating Alertmanager proxy Secret failed")
	}

	svc, err := t.factory.AlertmanagerService()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager Service failed")
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Alertmanager Service failed")
	}

	{
		// Create trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.AlertmanagerTrustedCABundle()
		if err != nil {
			return errors.Wrap(err, "initializing Alertmanager CA bundle ConfigMap failed")
		}

		cbs := &caBundleSyncer{
			client:  t.client,
			factory: t.factory,
			prefix:  "alertmanager",
		}
		trustedCA, err = cbs.syncTrustedCABundle(ctx, trustedCA)
		if err != nil {
			return errors.Wrap(err, "syncing Thanos Querier trusted CA bundle ConfigMap failed")
		}

		a, err := t.factory.AlertmanagerMain(host, trustedCA)
		if err != nil {
			return errors.Wrap(err, "initializing Alertmanager object failed")
		}

		err = t.client.CreateOrUpdateAlertmanager(ctx, a)
		if err != nil {
			return errors.Wrap(err, "reconciling Alertmanager object failed")
		}
		err = t.client.WaitForAlertmanager(ctx, a)
		if err != nil {
			return errors.Wrap(err, "waiting for Alertmanager object changes failed")
		}
	}
	pr, err := t.factory.AlertmanagerPrometheusRule()
	if err != nil {
		return errors.Wrap(err, "initializing alertmanager rules PrometheusRule failed")
	}
	err = t.client.CreateOrUpdatePrometheusRule(ctx, pr)
	if err != nil {
		return errors.Wrap(err, "reconciling alertmanager rules PrometheusRule failed")
	}

	smam, err := t.factory.AlertmanagerServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager ServiceMonitor failed")
	}

	// Alertmanager ServiceMonitor has been renamed from alertmanager to alertmanager-${config}.
	// This deletion ensures that the previous ServiceMonitor will be always removed after a CMO upgrade.
	// Refer https://github.com/prometheus-operator/kube-prometheus/pull/1471 for more info.
	t.client.DeleteServiceMonitorByNamespaceAndName(ctx, smam.Namespace, manifests.AlertmanagerLegacyServiceMonitorName)
	if err != nil {
		return errors.Wrap(err, "deleting legacy Alertmanager ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smam)
	return errors.Wrap(err, "reconciling Alertmanager ServiceMonitor failed")
}

func (t *AlertmanagerTask) destroy(ctx context.Context) error {
	r, err := t.factory.AlertmanagerRoute()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager Route failed")
	}

	err = t.client.DeleteRoute(ctx, r)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager Route failed")
	}

	s, err := t.factory.AlertmanagerConfig()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager configuration Secret failed")
	}

	err = t.client.DeleteSecret(ctx, s)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager configuration Secret failed")
	}

	rs, err := t.factory.AlertmanagerRBACProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager RBAC proxy Secret failed")
	}

	err = t.client.DeleteSecret(ctx, rs)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager RBAC proxy Secret failed")
	}

	rsm, err := t.factory.AlertmanagerRBACProxyMetricSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager RBAC proxy metric Secret failed")
	}

	err = t.client.DeleteSecret(ctx, rsm)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager RBAC proxy metric Secret failed")
	}

	cr, err := t.factory.AlertmanagerClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager ClusterRole failed")
	}

	err = t.client.DeleteClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager ClusterRole failed")
	}

	crb, err := t.factory.AlertmanagerClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager ClusterRoleBinding failed")
	}

	err = t.client.DeleteClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager ClusterRoleBinding failed")
	}

	sa, err := t.factory.AlertmanagerServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager ServiceAccount failed")
	}

	err = t.client.DeleteServiceAccount(ctx, sa)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager ServiceAccount failed")
	}

	ps, err := t.factory.AlertmanagerProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager proxy Secret failed")
	}

	err = t.client.DeleteSecret(ctx, ps)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager proxy Secret failed")
	}

	svc, err := t.factory.AlertmanagerService()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager Service failed")
	}

	err = t.client.DeleteService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager Service failed")
	}

	pdb, err := t.factory.AlertmanagerPodDisruptionBudget()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager PodDisruptionBudget object failed")
	}

	if pdb != nil {
		err = t.client.DeletePodDisruptionBudget(ctx, pdb)
		if err != nil {
			return errors.Wrap(err, "deleting Alertmanager PodDisruptionBudget object failed")
		}
	}

	{
		// Create trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.AlertmanagerTrustedCABundle()
		if err != nil {
			return errors.Wrap(err, "initializing Alertmanager CA bundle ConfigMap failed")
		}

		if err := t.client.DeleteConfigMap(ctx, trustedCA); err != nil {
			return errors.Wrap(err, "deleting Alertmanager trusted CA bundle failed")

		}

		a, err := t.factory.AlertmanagerMain("", trustedCA)
		if err != nil {
			return errors.Wrap(err, "initializing Alertmanager object failed")
		}

		err = t.client.DeleteAlertmanager(ctx, a)
		if err != nil {
			return errors.Wrap(err, "reconciling Alertmanager object failed")
		}
	}

	pr, err := t.factory.AlertmanagerPrometheusRule()
	if err != nil {
		return errors.Wrap(err, "initializing alertmanager rules PrometheusRule failed")
	}
	err = t.client.DeletePrometheusRule(ctx, pr)
	if err != nil {
		return errors.Wrap(err, "deleting alertmanager rules PrometheusRule failed")
	}

	smam, err := t.factory.AlertmanagerServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager ServiceMonitor failed")
	}

	err = t.client.DeleteServiceMonitor(ctx, smam)
	return errors.Wrap(err, "deleting Alertmanager ServiceMonitor failed")
}
