// Copyright 2019 The Cluster Monitoring Operator Authors
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

type PrometheusOperatorUserWorkloadTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewPrometheusOperatorUserWorkloadTask(client *client.Client, factory *manifests.Factory, config *manifests.Config) *PrometheusOperatorUserWorkloadTask {
	return &PrometheusOperatorUserWorkloadTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *PrometheusOperatorUserWorkloadTask) Run(ctx context.Context) error {
	if *t.config.ClusterMonitoringConfiguration.UserWorkloadEnabled {
		return t.create(ctx)
	}

	klog.V(3).Infof("UWM prometheus operator is disabled (because UWM is disabled), existing related resources are to be destroyed.")
	return t.destroy(ctx)
}

func (t *PrometheusOperatorUserWorkloadTask) create(ctx context.Context) error {
	netpol, err := t.factory.PrometheusOperatorUserWorkloadNetworkPolicy()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator NetworkPolicy failed: %w", err)
	}

	err = t.client.CreateOrUpdateNetworkPolicy(ctx, netpol)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus Operator NetworkPolicy failed: %w", err)
	}

	sa, err := t.factory.PrometheusOperatorUserWorkloadServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator ServiceAccount failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus Operator ServiceAccount failed: %w", err)
	}

	cr, err := t.factory.PrometheusOperatorUserWorkloadClusterRole()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator ClusterRole failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus Operator ClusterRole failed: %w", err)
	}

	crb, err := t.factory.PrometheusOperatorUserWorkloadClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator ClusterRoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus Operator ClusterRoleBinding failed: %w", err)
	}

	svc, err := t.factory.PrometheusOperatorUserWorkloadService()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus Operator Service failed: %w", err)
	}

	rpc, err := t.factory.PrometheusOperatorUserWorkloadCRBACProxySecret()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator RBAC proxy secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, rpc)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus Operator RBAC proxy secret failed: %w", err)
	}

	d, err := t.factory.PrometheusOperatorUserWorkloadDeployment()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator Deployment failed: %w", err)
	}

	err = t.client.CreateOrUpdateDeployment(ctx, d)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus Operator Deployment failed: %w", err)
	}

	arb, err := t.factory.PrometheusUserWorkloadAlertManagerRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Alertmanager Role Binding failed: %w", err)
	}

	if t.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.IsEnabled() {
		if err = t.client.CreateOrUpdateRoleBinding(ctx, arb); err != nil {
			return fmt.Errorf("reconciling UserWorkload Alertmanager Role Binding failed: %w", err)
		}
	} else {
		if err = t.client.DeleteRoleBinding(ctx, arb); err != nil {
			return fmt.Errorf("deleting UserWorkload Alertmanager Role Binding failed: %w", err)
		}
	}

	userCM, err := t.factory.PrometheusUserWorkloadConfigMap()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload ConfigMap failed: %w", err)
	}

	_, err = t.client.CreateIfNotExistConfigMap(ctx, userCM)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload ConfigMap failed: %w", err)
	}

	// The CRs will be created externally,
	// but we still have to wait for them here.
	err = t.client.AssurePrometheusOperatorCRsExist(ctx)
	if err != nil {
		return fmt.Errorf("waiting for Prometheus Operator CRs to become available failed: %w", err)
	}

	smpo, err := t.factory.PrometheusOperatorUserWorkloadServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator ServiceMonitor failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smpo)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus Operator ServiceMonitor failed: %w", err)
	}
	return nil
}

func (t *PrometheusOperatorUserWorkloadTask) destroy(ctx context.Context) error {
	dep, err := t.factory.PrometheusOperatorUserWorkloadDeployment()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator Deployment failed: %w", err)
	}

	err = t.client.DeleteDeployment(ctx, dep)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus Operator Deployment failed: %w", err)
	}

	sm, err := t.factory.PrometheusOperatorUserWorkloadServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator ServiceMonitor failed: %w", err)
	}

	err = t.client.DeleteServiceMonitor(ctx, sm)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus Operator ServiceMonitor failed: %w", err)
	}

	svc, err := t.factory.PrometheusOperatorUserWorkloadService()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator Service failed: %w", err)
	}

	err = t.client.DeleteService(ctx, svc)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus Operator Service failed: %w", err)
	}

	crb, err := t.factory.PrometheusOperatorUserWorkloadClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator ClusterRoleBinding failed: %w", err)
	}

	err = t.client.DeleteClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus Operator ClusterRoleBinding failed: %w", err)
	}

	arb, err := t.factory.PrometheusUserWorkloadAlertManagerRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Alertmanager Role Binding failed: %w", err)
	}

	err = t.client.DeleteRoleBinding(ctx, arb)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Alertmanager Role Binding failed: %w", err)
	}

	rpc, err := t.factory.PrometheusOperatorUserWorkloadCRBACProxySecret()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator RBAC proxy secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, rpc)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus Operator RBAC proxy secret failed: %w", err)
	}

	cr, err := t.factory.PrometheusOperatorUserWorkloadClusterRole()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator ClusterRole failed: %w", err)
	}

	err = t.client.DeleteClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus Operator ClusterRoleBinding failed: %w", err)
	}

	sa, err := t.factory.PrometheusOperatorUserWorkloadServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Operator ServiceAccount failed: %w", err)
	}

	err = t.client.DeleteServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("deleting Telemeter client ServiceAccount failed: %w", err)
	}
	return nil
}
