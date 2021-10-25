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
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"

	"github.com/pkg/errors"
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

	return t.destroy(ctx)
}

func (t *PrometheusOperatorUserWorkloadTask) create(ctx context.Context) error {
	sa, err := t.factory.PrometheusOperatorUserWorkloadServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ServiceAccount failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Operator ServiceAccount failed")
	}

	cr, err := t.factory.PrometheusOperatorUserWorkloadClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Operator ClusterRole failed")
	}

	crb, err := t.factory.PrometheusOperatorUserWorkloadClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Operator ClusterRoleBinding failed")
	}

	svc, err := t.factory.PrometheusOperatorUserWorkloadService()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator Service failed")
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Operator Service failed")
	}

	rpc, err := t.factory.PrometheusOperatorUserWorkloadCRBACProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator RBAC proxy secret failed")
	}

	err = t.client.CreateOrUpdateSecret(ctx, rpc)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Operator RBAC proxy secret failed")
	}

	d, err := t.factory.PrometheusOperatorUserWorkloadDeployment()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator Deployment failed")
	}

	err = t.client.CreateOrUpdateDeployment(ctx, d)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Operator Deployment failed")
	}

	arb, err := t.factory.PrometheusUserWorkloadAlertManagerRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Alertmanager Role Binding failed")
	}

	if t.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.IsEnabled() {
		if err = t.client.CreateOrUpdateRoleBinding(ctx, arb); err != nil {
			return errors.Wrap(err, "reconciling UserWorkload Alertmanager Role Binding failed")
		}
	} else {
		if err = t.client.DeleteRoleBinding(ctx, arb); err != nil {
			return errors.Wrap(err, "deleting UserWorkload Alertmanager Role Binding failed")
		}
	}

	// The CRs will be created externally,
	// but we still have to wait for them here.
	err = t.client.AssurePrometheusOperatorCRsExist(ctx)
	if err != nil {
		return errors.Wrap(err, "waiting for Prometheus Operator CRs to become available failed")
	}

	smpo, err := t.factory.PrometheusOperatorUserWorkloadServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smpo)
	return errors.Wrap(err, "reconciling UserWorkload Prometheus Operator ServiceMonitor failed")
}

func (t *PrometheusOperatorUserWorkloadTask) destroy(ctx context.Context) error {
	dep, err := t.factory.PrometheusOperatorUserWorkloadDeployment()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator Deployment failed")
	}

	err = t.client.DeleteDeployment(ctx, dep)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Operator Deployment failed")
	}

	sm, err := t.factory.PrometheusOperatorUserWorkloadServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ServiceMonitor failed")
	}

	err = t.client.DeleteServiceMonitor(ctx, sm)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Operator ServiceMonitor failed")
	}

	svc, err := t.factory.PrometheusOperatorUserWorkloadService()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator Service failed")
	}

	err = t.client.DeleteService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Operator Service failed")
	}

	crb, err := t.factory.PrometheusOperatorUserWorkloadClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ClusterRoleBinding failed")
	}

	err = t.client.DeleteClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Operator ClusterRoleBinding failed")
	}

	arb, err := t.factory.PrometheusUserWorkloadAlertManagerRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Alertmanager Role Binding failed")
	}

	err = t.client.DeleteRoleBinding(ctx, arb)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Alertmanager Role Binding failed")
	}

	rpc, err := t.factory.PrometheusOperatorUserWorkloadCRBACProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator RBAC proxy secret failed")
	}

	err = t.client.DeleteSecret(ctx, rpc)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Operator RBAC proxy secret failed")
	}

	cr, err := t.factory.PrometheusOperatorUserWorkloadClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ClusterRole failed")
	}

	err = t.client.DeleteClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Operator ClusterRoleBinding failed")
	}

	sa, err := t.factory.PrometheusOperatorUserWorkloadServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ServiceAccount failed")
	}

	err = t.client.DeleteServiceAccount(ctx, sa)
	return errors.Wrap(err, "deleting Telemeter client ServiceAccount failed")
}
