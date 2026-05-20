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

type NodeExporterTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewNodeExporterTask(client *client.Client, factory *manifests.Factory) *NodeExporterTask {
	return &NodeExporterTask{
		client:  client,
		factory: factory,
	}
}

func (t *NodeExporterTask) Run(ctx context.Context) error {
	scc, err := t.factory.NodeExporterSecurityContextConstraints()
	if err != nil {
		return fmt.Errorf("initializing node-exporter SecurityContextConstraints failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecurityContextConstraints(ctx, scc)
	if err != nil {
		return fmt.Errorf("reconciling node-exporter SecurityContextConstraints failed: %w", err)
	}

	sa, err := t.factory.NodeExporterServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing node-exporter ServiceAccount failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("reconciling node-exporter ServiceAccount failed: %w", err)
	}

	cr, err := t.factory.NodeExporterClusterRole()
	if err != nil {
		return fmt.Errorf("initializing node-exporter ClusterRole failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("reconciling node-exporter ClusterRole failed: %w", err)
	}

	crb, err := t.factory.NodeExporterClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing node-exporter ClusterRoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("reconciling node-exporter ClusterRoleBinding failed: %w", err)
	}

	nes, err := t.factory.NodeExporterRBACProxySecret()
	if err != nil {
		return fmt.Errorf("intializing node-exporter rbac proxy secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, nes)
	if err != nil {
		return fmt.Errorf("creating node-exporter rbac proxy secret failed: %w", err)
	}
	svc, err := t.factory.NodeExporterService()
	if err != nil {
		return fmt.Errorf("initializing node-exporter Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling node-exporter Service failed: %w", err)
	}

	cm, err := t.factory.NodeExporterAcceleratorsCollectorConfigMap()
	if err != nil {
		return fmt.Errorf("initializing node-exporter accelerators collector ConfigMap failed: %w", err)
	}
	err = t.client.CreateOrUpdateConfigMap(ctx, cm)
	if err != nil {
		return fmt.Errorf("reconciling node-exporter accelerators collector ConfigMap failed: %w", err)
	}

	ds, err := t.factory.NodeExporterDaemonSet()
	if err != nil {
		return fmt.Errorf("initializing node-exporter DaemonSet failed: %w", err)
	}

	err = t.client.CreateOrUpdateDaemonSet(ctx, ds)
	if err != nil {
		return fmt.Errorf("reconciling node-exporter DaemonSet failed: %w", err)
	}

	pr, err := t.factory.NodeExporterPrometheusRule()
	if err != nil {
		return fmt.Errorf("initializing node-exporter rules PrometheusRule failed: %w", err)
	}
	err = t.client.CreateOrUpdatePrometheusRule(ctx, pr)
	if err != nil {
		return fmt.Errorf("reconciling node-exporter rules PrometheusRule failed: %w", err)
	}

	sms, err := t.factory.NodeExporterServiceMonitors()
	if err != nil {
		return fmt.Errorf("initializing node-exporter ServiceMonitors failed: %w", err)
	}

	for _, sm := range sms {
		err = t.client.CreateOrUpdateServiceMonitor(ctx, sm)
		if err != nil {
			return fmt.Errorf("reconciling %s/%s ServiceMonitor failed: %w", sm.Namespace, sm.Name, err)
		}
	}

	return nil
}
