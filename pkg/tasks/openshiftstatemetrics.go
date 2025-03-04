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

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

type OpenShiftStateMetricsTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewOpenShiftStateMetricsTask(client *client.Client, factory *manifests.Factory) *OpenShiftStateMetricsTask {
	return &OpenShiftStateMetricsTask{
		client:  client,
		factory: factory,
	}
}

func (t *OpenShiftStateMetricsTask) Run(ctx context.Context) error {
	sa, err := t.factory.OpenShiftStateMetricsServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing openshift-state-metrics Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("reconciling openshift-state-metrics ServiceAccount failed: %w", err)
	}

	cr, err := t.factory.OpenShiftStateMetricsClusterRole()
	if err != nil {
		return fmt.Errorf("initializing openshift-state-metrics ClusterRole failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("reconciling openshift-state-metrics ClusterRole failed: %w", err)
	}

	crb, err := t.factory.OpenShiftStateMetricsClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing openshift-state-metrics ClusterRoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("reconciling openshift-state-metrics ClusterRoleBinding failed: %w", err)
	}

	svc, err := t.factory.OpenShiftStateMetricsService()
	if err != nil {
		return fmt.Errorf("initializing openshift-state-metrics Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling openshift-state-metrics Service failed: %w", err)
	}

	rs, err := t.factory.OpenShiftStateMetricsRBACProxySecret()
	if err != nil {
		return fmt.Errorf("initializing openshift-state-metrics RBAC proxy Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, rs)
	if err != nil {
		return fmt.Errorf("creating openshift-state-metrics RBAC proxy Secret failed: %w", err)
	}

	dep, err := t.factory.OpenShiftStateMetricsDeployment()
	if err != nil {
		return fmt.Errorf("initializing openshift-state-metrics Deployment failed: %w", err)
	}

	err = t.client.CreateOrUpdateDeployment(ctx, dep)
	if err != nil {
		return fmt.Errorf("reconciling openshift-state-metrics Deployment failed: %w", err)
	}

	sm, err := t.factory.OpenShiftStateMetricsServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing openshift-state-metrics ServiceMonitor failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, sm)
	if err != nil {
		return fmt.Errorf("reconciling openshift-state-metrics ServiceMonitor failed: %w", err)
	}
	return nil
}
