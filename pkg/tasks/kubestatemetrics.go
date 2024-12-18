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

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

type KubeStateMetricsTask struct {
	client           *client.Client
	factory          *manifests.Factory
	enableCRSMetrics bool
}

func NewKubeStateMetricsTask(client *client.Client, factory *manifests.Factory, enableCRSMetrics bool) *KubeStateMetricsTask {
	return &KubeStateMetricsTask{
		client:           client,
		factory:          factory,
		enableCRSMetrics: enableCRSMetrics,
	}
}

func (t *KubeStateMetricsTask) Run(ctx context.Context) error {
	sa, err := t.factory.KubeStateMetricsServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing kube-state-metrics Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("reconciling kube-state-metrics ServiceAccount failed: %w", err)
	}

	cr, err := t.factory.KubeStateMetricsClusterRole()
	if err != nil {
		return fmt.Errorf("initializing kube-state-metrics ClusterRole failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("reconciling kube-state-metrics ClusterRole failed: %w", err)
	}

	crb, err := t.factory.KubeStateMetricsClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing kube-state-metrics ClusterRoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("reconciling kube-state-metrics ClusterRoleBinding failed: %w", err)
	}

	rs, err := t.factory.KubeStateMetricsRBACProxySecret()
	if err != nil {
		return fmt.Errorf("initializing kube-state-metrics RBAC proxy Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, rs)
	if err != nil {
		return fmt.Errorf("creating kube-state-metrics RBAC proxy Secret failed: %w", err)
	}

	svc, err := t.factory.KubeStateMetricsService()
	if err != nil {
		return fmt.Errorf("initializing kube-state-metrics Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling kube-state-metrics Service failed: %w", err)
	}

	cm, err := t.factory.KubeStateMetricsCRSConfigMap()
	if err != nil {
		return fmt.Errorf("initializing kube-state-metrics custom-resource-state ConfigMap failed: %w", err)
	}

	err = t.client.CreateOrUpdateConfigMap(ctx, cm)
	if err != nil {
		return fmt.Errorf("reconciling %s/%s ConfigMap failed: %w", cm.Namespace, cm.Name, err)
	}

	dep, err := t.factory.KubeStateMetricsDeployment(t.enableCRSMetrics)
	if err != nil {
		return fmt.Errorf("initializing kube-state-metrics Deployment failed: %w", err)
	}

	err = t.client.CreateOrUpdateDeployment(ctx, dep)
	if err != nil {
		return fmt.Errorf("reconciling kube-state-metrics Deployment failed: %w", err)
	}

	pr, err := t.factory.KubeStateMetricsPrometheusRule()
	if err != nil {
		return fmt.Errorf("initializing kube-state-metrics rules PrometheusRule failed: %w", err)
	}
	err = t.client.CreateOrUpdatePrometheusRule(ctx, pr)
	if err != nil {
		return fmt.Errorf("reconciling kube-state-metrics rules PrometheusRule failed: %w", err)
	}

	sms, err := t.factory.KubeStateMetricsServiceMonitors()
	if err != nil {
		return fmt.Errorf("initializing kube-state-metrics ServiceMonitors failed: %w", err)
	}
	for _, sm := range sms {
		err = t.client.CreateOrUpdateServiceMonitor(ctx, sm)
		if err != nil {
			return fmt.Errorf("reconciling %s/%s ServiceMonitor failed: %w", sm.Namespace, sm.Name, err)
		}
	}

	return nil
}
