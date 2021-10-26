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

type KubeStateMetricsTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewKubeStateMetricsTask(client *client.Client, factory *manifests.Factory) *KubeStateMetricsTask {
	return &KubeStateMetricsTask{
		client:  client,
		factory: factory,
	}
}

func (t *KubeStateMetricsTask) Run(ctx context.Context) error {
	sa, err := t.factory.KubeStateMetricsServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics Service failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return errors.Wrap(err, "reconciling kube-state-metrics ServiceAccount failed")
	}

	cr, err := t.factory.KubeStateMetricsClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "reconciling kube-state-metrics ClusterRole failed")
	}

	crb, err := t.factory.KubeStateMetricsClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "reconciling kube-state-metrics ClusterRoleBinding failed")
	}

	rs, err := t.factory.KubeStateMetricsRBACProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics RBAC proxy Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ctx, rs)
	if err != nil {
		return errors.Wrap(err, "creating kube-state-metrics RBAC proxy Secret failed")
	}

	svc, err := t.factory.KubeStateMetricsService()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics Service failed")
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "reconciling kube-state-metrics Service failed")
	}

	dep, err := t.factory.KubeStateMetricsDeployment()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics Deployment failed")
	}

	err = t.client.CreateOrUpdateDeployment(ctx, dep)
	if err != nil {
		return errors.Wrap(err, "reconciling kube-state-metrics Deployment failed")
	}

	pr, err := t.factory.KubeStateMetricsPrometheusRule()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics rules PrometheusRule failed")
	}
	err = t.client.CreateOrUpdatePrometheusRule(ctx, pr)
	if err != nil {
		return errors.Wrap(err, "reconciling kube-state-metrics rules PrometheusRule failed")
	}

	sm, err := t.factory.KubeStateMetricsServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, sm)
	if err != nil {
		errors.Wrap(err, "reconciling kube-state-metrics ServiceMonitor failed")
	}

	return nil
}
