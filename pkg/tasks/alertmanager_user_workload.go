// Copyright 2022 The Cluster Monitoring Operator Authors
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
	"k8s.io/apimachinery/pkg/types"
)

type AlertmanagerUserWorkloadTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewAlertmanagerUserWorkloadTask(
	client *client.Client,
	factory *manifests.Factory,
	config *manifests.Config,
) *AlertmanagerUserWorkloadTask {
	return &AlertmanagerUserWorkloadTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *AlertmanagerUserWorkloadTask) Run(ctx context.Context) error {
	if t.config.UserWorkloadConfiguration.Alertmanager.Enabled {
		return t.create(ctx)
	}

	return t.destroy(ctx)
}

func (t *AlertmanagerUserWorkloadTask) create(ctx context.Context) error {
	s, err := t.factory.AlertmanagerUserWorkloadSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload configuration Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ctx, s)
	if err != nil {
		return errors.Wrap(err, "creating Alertmanager User Workload configuration Secret failed")
	}

	pdb, err := t.factory.AlertmanagerUserWorkloadPodDisruptionBudget()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload PodDisruptionBudget object failed")
	}

	if pdb != nil {
		err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb)
		if err != nil {
			return errors.Wrap(err, "reconciling Alertmanager User Workload PodDisruptionBudget object failed")
		}
	}

	s, err = t.factory.AlertmanagerUserWorkloadRBACProxyTenancySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload RBAC proxy tenancy Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ctx, s)
	if err != nil {
		return errors.Wrap(err, "creating Alertmanager User Workload RBAC proxy tenancy Secret failed")
	}

	rsm, err := t.factory.AlertmanagerUserWorkloadRBACProxyMetricSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload RBAC proxy metric Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ctx, rsm)
	if err != nil {
		return errors.Wrap(err, "creating Alertmanager User Workload RBAC proxy metric Secret failed")
	}

	if t.config.UserWorkloadConfiguration.Alertmanager.Secrets != nil {
		for _, secret := range t.config.UserWorkloadConfiguration.Alertmanager.Secrets {
			obj := types.NamespacedName{
				Name:      secret,
				Namespace: "openshift-user-workload-monitoring",
			}
			if _, err = t.client.WaitForSecretByNsName(ctx, obj); err != nil {
				return errors.Wrapf(err, "failed to find Alertmanager secret %q", secret)
			}
		}
	}

	cr, err := t.factory.AlertmanagerUserWorkloadClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "reconciling Alertmanager User Workload ClusterRole failed")
	}

	crb, err := t.factory.AlertmanagerUserWorkloadClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanage User Workload ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "reconciling Alertmanager User Workload ClusterRoleBinding failed")
	}

	sa, err := t.factory.AlertmanagerUserWorkloadServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload ServiceAccount failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return errors.Wrap(err, "reconciling Alertmanager User Workload ServiceAccount failed")
	}

	svc, err := t.factory.AlertmanagerUserWorkloadService()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload Service failed")
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Alertmanager User Workload Service failed")
	}

	{
		// Create trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.AlertmanagerUserWorkloadTrustedCABundle()
		if err != nil {
			return errors.Wrap(err, "initializing Alertmanager User Workload CA bundle ConfigMap failed")
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

		a, err := t.factory.AlertmanagerUserWorkload(trustedCA)
		if err != nil {
			return errors.Wrap(err, "initializing Alertmanager User Workload object failed")
		}

		err = t.client.CreateOrUpdateAlertmanager(ctx, a)
		if err != nil {
			return errors.Wrap(err, "reconciling Alertmanager User Workload object failed")
		}
		err = t.client.WaitForAlertmanager(ctx, a)
		if err != nil {
			return errors.Wrap(err, "waiting for Alertmanager User Workload object changes failed")
		}
	}

	smam, err := t.factory.AlertmanagerUserWorkloadServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smam)
	return errors.Wrap(err, "reconciling Alertmanager User Workload ServiceMonitor failed")
}

func (t *AlertmanagerUserWorkloadTask) destroy(ctx context.Context) error {
	s, err := t.factory.AlertmanagerUserWorkloadSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload configuration Secret failed")
	}

	err = t.client.DeleteSecret(ctx, s)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager User Workload configuration Secret failed")
	}

	s, err = t.factory.AlertmanagerUserWorkloadRBACProxyTenancySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload RBAC proxy tenancy Secret failed")
	}

	err = t.client.DeleteSecret(ctx, s)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager User Workload RBAC proxy tenancy Secret failed")
	}

	rsm, err := t.factory.AlertmanagerUserWorkloadRBACProxyMetricSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload RBAC proxy metric Secret failed")
	}

	err = t.client.DeleteSecret(ctx, rsm)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager User Workload RBAC proxy metric Secret failed")
	}

	cr, err := t.factory.AlertmanagerUserWorkloadClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload ClusterRole failed")
	}

	err = t.client.DeleteClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager User Workload ClusterRole failed")
	}

	crb, err := t.factory.AlertmanagerUserWorkloadClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload ClusterRoleBinding failed")
	}

	err = t.client.DeleteClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager User Workload ClusterRoleBinding failed")
	}

	sa, err := t.factory.AlertmanagerUserWorkloadServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload ServiceAccount failed")
	}

	err = t.client.DeleteServiceAccount(ctx, sa)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager User Workload ServiceAccount failed")
	}

	svc, err := t.factory.AlertmanagerUserWorkloadService()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload Service failed")
	}

	err = t.client.DeleteService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "deleting Alertmanager User Workload Service failed")
	}

	pdb, err := t.factory.AlertmanagerUserWorkloadPodDisruptionBudget()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload PodDisruptionBudget object failed")
	}

	if pdb != nil {
		err = t.client.DeletePodDisruptionBudget(ctx, pdb)
		if err != nil {
			return errors.Wrap(err, "deleting Alertmanager User Workload PodDisruptionBudget object failed")
		}
	}

	{
		// Delete trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.AlertmanagerUserWorkloadTrustedCABundle()
		if err != nil {
			return errors.Wrap(err, "initializing Alertmanager User Workload CA bundle ConfigMap failed")
		}

		if err := t.client.DeleteConfigMap(ctx, trustedCA); err != nil {
			return errors.Wrap(err, "deleting Alertmanager User Workload trusted CA bundle failed")

		}

		a, err := t.factory.AlertmanagerUserWorkload(trustedCA)
		if err != nil {
			return errors.Wrap(err, "initializing Alertmanager User Workload object failed")
		}

		err = t.client.DeleteAlertmanager(ctx, a)
		if err != nil {
			return errors.Wrap(err, "deleting Alertmanager User Workload object failed")
		}
	}

	smam, err := t.factory.AlertmanagerUserWorkloadServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager User Workload ServiceMonitor failed")
	}

	err = t.client.DeleteServiceMonitor(ctx, smam)
	return errors.Wrap(err, "deleting Alertmanager User Workload ServiceMonitor failed")
}
