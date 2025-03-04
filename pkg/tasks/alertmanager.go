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
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
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

	klog.V(3).Infof("Main alertmanager is disabled, existing related resources are to be destroyed.")
	return t.destroy(ctx)
}

func (t *AlertmanagerTask) create(ctx context.Context) error {
	hasRoutes, err := t.client.HasRouteCapability(ctx)
	if err != nil {
		return fmt.Errorf("checking for Route capability failed: %w", err)
	}
	if hasRoutes {
		r, err := t.factory.AlertmanagerRoute()
		if err != nil {
			return fmt.Errorf("initializing Alertmanager Route failed: %w", err)
		}

		err = t.client.CreateOrUpdateRoute(ctx, r)
		if err != nil {
			return fmt.Errorf("reconciling Alertmanager Route failed: %w", err)
		}

		_, err = t.client.WaitForRouteReady(ctx, r)
		if err != nil {
			return fmt.Errorf("waiting for Alertmanager Route to become ready failed: %w", err)
		}
	}

	s, err := t.factory.AlertmanagerConfig()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager configuration Secret failed: %w", err)
	}

	err = t.client.CreateIfNotExistSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("creating Alertmanager configuration Secret failed: %w", err)
	}

	pdb, err := t.factory.AlertmanagerPodDisruptionBudget()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager PodDisruptionBudget object failed: %w", err)
	}

	if pdb != nil {
		err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb)
		if err != nil {
			return fmt.Errorf("reconciling Alertmanager PodDisruptionBudget object failed: %w", err)
		}
	}

	rs, err := t.factory.AlertmanagerRBACProxySecret()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager RBAC proxy Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, rs)
	if err != nil {
		return fmt.Errorf("creating Alertmanager RBAC proxy Secret failed: %w", err)
	}

	rsm, err := t.factory.AlertmanagerRBACProxyMetricSecret()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager RBAC proxy metric Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, rsm)
	if err != nil {
		return fmt.Errorf("creating Alertmanager RBAC proxy metric Secret failed: %w", err)
	}

	if t.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Secrets != nil {
		for _, secret := range t.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Secrets {
			obj := types.NamespacedName{
				Name:      secret,
				Namespace: t.client.Namespace(),
			}
			if _, err = t.client.WaitForSecretByNsName(ctx, obj); err != nil {
				return fmt.Errorf("failed to find Alertmanager secret %q: %w", secret, err)
			}
		}
	}

	cr, err := t.factory.AlertmanagerClusterRole()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager ClusterRole failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("reconciling Alertmanager ClusterRole failed: %w", err)
	}

	crb, err := t.factory.AlertmanagerClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager ClusterRoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("reconciling Alertmanager ClusterRoleBinding failed: %w", err)
	}

	sa, err := t.factory.AlertmanagerServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager ServiceAccount failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("reconciling Alertmanager ServiceAccount failed: %w", err)
	}

	ps, err := t.factory.AlertmanagerRBACProxyWebSecret()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager proxy web Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, ps)
	if err != nil {
		return fmt.Errorf("creating Alertmanager proxy web Secret failed: %w", err)
	}

	svc, err := t.factory.AlertmanagerService()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling Alertmanager Service failed: %w", err)
	}

	{
		// Create trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.AlertmanagerTrustedCABundle()
		if err != nil {
			return fmt.Errorf("initializing Alertmanager CA bundle ConfigMap failed: %w", err)
		}

		err = t.client.CreateOrUpdateConfigMap(ctx, trustedCA)
		if err != nil {
			return fmt.Errorf("reconciling Alertmanager trusted CA bundle ConfigMap failed: %w", err)
		}

		a, err := t.factory.AlertmanagerMain()
		if err != nil {
			return fmt.Errorf("initializing Alertmanager object failed: %w", err)
		}

		err = t.client.CreateOrUpdateAlertmanager(ctx, a)
		if err != nil {
			return fmt.Errorf("reconciling Alertmanager object failed: %w", err)
		}
		err = t.client.WaitForAlertmanager(ctx, a)
		if err != nil {
			return fmt.Errorf("waiting for Alertmanager object changes failed: %w", err)
		}
	}
	pr, err := t.factory.AlertmanagerPrometheusRule()
	if err != nil {
		return fmt.Errorf("initializing alertmanager rules PrometheusRule failed: %w", err)
	}
	err = t.client.CreateOrUpdatePrometheusRule(ctx, pr)
	if err != nil {
		return fmt.Errorf("reconciling alertmanager rules PrometheusRule failed: %w", err)
	}

	smam, err := t.factory.AlertmanagerServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager ServiceMonitor failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smam)
	if err != nil {
		return fmt.Errorf("reconciling Alertmanager ServiceMonitor failed: %w", err)
	}

	return nil
}

func (t *AlertmanagerTask) destroy(ctx context.Context) error {
	r, err := t.factory.AlertmanagerRoute()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager Route failed: %w", err)
	}

	err = t.client.DeleteRoute(ctx, r)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager Route failed: %w", err)
	}

	s, err := t.factory.AlertmanagerConfig()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager configuration Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager configuration Secret failed: %w", err)
	}

	rs, err := t.factory.AlertmanagerRBACProxySecret()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager RBAC proxy Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, rs)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager RBAC proxy Secret failed: %w", err)
	}

	rsm, err := t.factory.AlertmanagerRBACProxyMetricSecret()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager RBAC proxy metric Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, rsm)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager RBAC proxy metric Secret failed: %w", err)
	}

	cr, err := t.factory.AlertmanagerClusterRole()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager ClusterRole failed: %w", err)
	}

	err = t.client.DeleteClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager ClusterRole failed: %w", err)
	}

	crb, err := t.factory.AlertmanagerClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager ClusterRoleBinding failed: %w", err)
	}

	err = t.client.DeleteClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager ClusterRoleBinding failed: %w", err)
	}

	sa, err := t.factory.AlertmanagerServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager ServiceAccount failed: %w", err)
	}

	err = t.client.DeleteServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager ServiceAccount failed: %w", err)
	}

	ps, err := t.factory.AlertmanagerRBACProxyWebSecret()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager proxy web Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, ps)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager proxy Secret failed: %w", err)
	}

	svc, err := t.factory.AlertmanagerService()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager Service failed: %w", err)
	}

	err = t.client.DeleteService(ctx, svc)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager Service failed: %w", err)
	}

	pdb, err := t.factory.AlertmanagerPodDisruptionBudget()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager PodDisruptionBudget object failed: %w", err)
	}

	if pdb != nil {
		err = t.client.DeletePodDisruptionBudget(ctx, pdb)
		if err != nil {
			return fmt.Errorf("deleting Alertmanager PodDisruptionBudget object failed: %w", err)
		}
	}

	{
		// Delete trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.AlertmanagerTrustedCABundle()
		if err != nil {
			return fmt.Errorf("initializing Alertmanager CA bundle ConfigMap failed: %w", err)
		}

		if err := t.client.DeleteConfigMap(ctx, trustedCA); err != nil {
			return fmt.Errorf("deleting Alertmanager trusted CA bundle failed: %w", err)
		}

		a, err := t.factory.AlertmanagerMain()
		if err != nil {
			return fmt.Errorf("initializing Alertmanager object failed: %w", err)
		}

		err = t.client.DeleteAlertmanager(ctx, a)
		if err != nil {
			return fmt.Errorf("deleting Alertmanager object failed: %w", err)
		}
	}

	// Delete the rules only if both platform and UWM Alertmanagers are disabled.
	if !t.config.UserWorkloadConfiguration.Alertmanager.Enabled {
		pr, err := t.factory.AlertmanagerPrometheusRule()
		if err != nil {
			return fmt.Errorf("initializing alertmanager rules PrometheusRule failed: %w", err)
		}
		err = t.client.DeletePrometheusRule(ctx, pr)
		if err != nil {
			return fmt.Errorf("deleting alertmanager rules PrometheusRule failed: %w", err)
		}
	}

	smam, err := t.factory.AlertmanagerServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing Alertmanager ServiceMonitor failed: %w", err)
	}

	err = t.client.DeleteServiceMonitor(ctx, smam)
	if err != nil {
		return fmt.Errorf("deleting Alertmanager ServiceMonitor failed: %w", err)
	}
	return nil
}
