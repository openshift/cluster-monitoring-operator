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
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
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

	klog.V(3).Infof("UWM alertmanager is disabled, existing related resources are to be destroyed.")
	return t.destroy(ctx)
}

func (t *AlertmanagerUserWorkloadTask) create(ctx context.Context) error {
	s, err := t.factory.AlertmanagerUserWorkloadSecret()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload configuration Secret failed: %w", err)
	}

	err = t.client.CreateIfNotExistSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("creating Alertmanager User Workload configuration Secret failed: %w", err)
	}

	pdb, err := t.factory.AlertmanagerUserWorkloadPodDisruptionBudget()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload PodDisruptionBudget object failed: %w", err)
	}

	if pdb != nil {
		err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb)
		if err != nil {
			return fmt.Errorf("reconciling Alertmanager User Workload PodDisruptionBudget object failed: %w", err)
		}
	}

	s, err = t.factory.AlertmanagerUserWorkloadRBACProxySecret()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload RBAC proxy Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("creating Alertmanager User Workload RBAC proxy Secret failed: %w", err)
	}

	s, err = t.factory.AlertmanagerUserWorkloadRBACProxyTenancySecret()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload RBAC proxy tenancy Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("creating Alertmanager User Workload RBAC proxy tenancy Secret failed: %w", err)
	}

	rsm, err := t.factory.AlertmanagerUserWorkloadRBACProxyMetricSecret()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload RBAC proxy metric Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, rsm)
	if err != nil {
		return fmt.Errorf("creating Alertmanager User Workload RBAC proxy metric Secret failed: %w", err)
	}

	if t.config.UserWorkloadConfiguration.Alertmanager.Secrets != nil {
		for _, secret := range t.config.UserWorkloadConfiguration.Alertmanager.Secrets {
			obj := types.NamespacedName{
				Name:      secret,
				Namespace: "openshift-user-workload-monitoring",
			}
			if _, err = t.client.WaitForSecretByNsName(ctx, obj); err != nil {
				return fmt.Errorf("failed to find Alertmanager secret %q: %w", secret, err)
			}
		}
	}

	cr, err := t.factory.AlertmanagerUserWorkloadClusterRole()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload ClusterRole failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("reconciling Alertmanager User Workload ClusterRole failed: %w", err)
	}

	crb, err := t.factory.AlertmanagerUserWorkloadClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Alertmanage User Workload ClusterRoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("reconciling Alertmanager User Workload ClusterRoleBinding failed: %w", err)
	}

	sa, err := t.factory.AlertmanagerUserWorkloadServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload ServiceAccount failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("reconciling Alertmanager User Workload ServiceAccount failed: %w", err)
	}

	svc, err := t.factory.AlertmanagerUserWorkloadService()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling Alertmanager User Workload Service failed: %w", err)
	}

	{
		trustedCA, err := t.factory.AlertmanagerUserWorkloadTrustedCABundle()
		if err != nil {
			return fmt.Errorf("initializing Alertmanager User Workload CA bundle ConfigMap failed: %w", err)
		}

		err = t.client.CreateOrUpdateConfigMap(ctx, trustedCA)
		if err != nil {
			return fmt.Errorf("reconciling Alertmanager User Workload trusted CA bundle ConfigMap failed: %w", err)
		}

		a, err := t.factory.AlertmanagerUserWorkload()
		if err != nil {
			return fmt.Errorf("initializing Alertmanager User Workload object failed: %w", err)
		}

		err = t.client.CreateOrUpdateAlertmanager(ctx, a)
		if err != nil {
			return fmt.Errorf("reconciling Alertmanager User Workload object failed: %w", err)
		}
		err = t.client.WaitForAlertmanager(ctx, a)
		if err != nil {
			return fmt.Errorf("waiting for Alertmanager User Workload object changes failed: %w", err)
		}
	}

	smam, err := t.factory.AlertmanagerUserWorkloadServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload ServiceMonitor failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smam)
	if err != nil {
		return fmt.Errorf("reconciling Alertmanager User Workload ServiceMonitor failed: %w", err)
	}

	return nil
}

func (t *AlertmanagerUserWorkloadTask) destroy(ctx context.Context) error {
	s, err := t.factory.AlertmanagerUserWorkloadSecret()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload configuration Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager User Workload configuration Secret failed: %w", err)
	}

	s, err = t.factory.AlertmanagerUserWorkloadRBACProxySecret()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload RBAC proxy  Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager User Workload RBAC proxy Secret failed: %w", err)
	}

	s, err = t.factory.AlertmanagerUserWorkloadRBACProxyTenancySecret()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload RBAC proxy tenancy Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager User Workload RBAC proxy tenancy Secret failed: %w", err)
	}

	rsm, err := t.factory.AlertmanagerUserWorkloadRBACProxyMetricSecret()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload RBAC proxy metric Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, rsm)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager User Workload RBAC proxy metric Secret failed: %w", err)
	}

	cr, err := t.factory.AlertmanagerUserWorkloadClusterRole()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload ClusterRole failed: %w", err)
	}

	err = t.client.DeleteClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager User Workload ClusterRole failed: %w", err)
	}

	crb, err := t.factory.AlertmanagerUserWorkloadClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload ClusterRoleBinding failed: %w", err)
	}

	err = t.client.DeleteClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager User Workload ClusterRoleBinding failed: %w", err)
	}

	sa, err := t.factory.AlertmanagerUserWorkloadServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload ServiceAccount failed: %w", err)
	}

	err = t.client.DeleteServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager User Workload ServiceAccount failed: %w", err)
	}

	svc, err := t.factory.AlertmanagerUserWorkloadService()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload Service failed: %w", err)
	}

	err = t.client.DeleteService(ctx, svc)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager User Workload Service failed: %w", err)
	}

	pdb, err := t.factory.AlertmanagerUserWorkloadPodDisruptionBudget()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager User Workload PodDisruptionBudget object failed: %w", err)
	}

	if pdb != nil {
		err = t.client.DeletePodDisruptionBudget(ctx, pdb)
		if err != nil {
			return fmt.Errorf("deleting Alertmanager User Workload PodDisruptionBudget object failed: %w", err)
		}
	}

	{
		// Delete trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.AlertmanagerUserWorkloadTrustedCABundle()
		if err != nil {
			return fmt.Errorf("initializing Alertmanager User Workload CA bundle ConfigMap failed: %w", err)
		}

		if err := t.client.DeleteConfigMap(ctx, trustedCA); err != nil {
			return fmt.Errorf("deleting Alertmanager User Workload trusted CA bundle failed: %w", err)
		}

		a, err := t.factory.AlertmanagerUserWorkload()
		if err != nil {
			return fmt.Errorf("initializing Alertmanager User Workload object failed: %w", err)
		}

		err = t.client.DeleteAlertmanager(ctx, a)
		if err != nil {
			return fmt.Errorf("deleting Alertmanager User Workload object failed: %w", err)
		}
	}

	smam, err := t.factory.AlertmanagerUserWorkloadServiceMonitor()
	if err != nil {
		return fmt.Errorf(
			"initializing Alertmanager User Workload ServiceMonitor failed: %w", err)
	}

	err = t.client.DeleteServiceMonitor(ctx, smam)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager User Workload ServiceMonitor failed: %w", err)
	}

	return nil
}
