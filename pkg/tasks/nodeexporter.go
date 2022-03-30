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

func (t *NodeExporterTask) Run(ctx context.Context) client.StateErrors {
	return stateErrors(t.create(ctx))
}

func (t *NodeExporterTask) create(ctx context.Context) error {
	scc, err := t.factory.NodeExporterSecurityContextConstraints()
	if err != nil {
		return errors.Wrap(err, "initializing node-exporter SecurityContextConstraints failed")
	}

	err = t.client.CreateOrUpdateSecurityContextConstraints(ctx, scc)
	if err != nil {
		return errors.Wrap(err, "reconciling node-exporter SecurityContextConstraints failed")
	}

	sa, err := t.factory.NodeExporterServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing node-exporter ServiceAccount failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return errors.Wrap(err, "reconciling node-exporter ServiceAccount failed")
	}

	cr, err := t.factory.NodeExporterClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing node-exporter ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "reconciling node-exporter ClusterRole failed")
	}

	crb, err := t.factory.NodeExporterClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing node-exporter ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "reconciling node-exporter ClusterRoleBinding failed")
	}

	nes, err := t.factory.NodeExporterRBACProxySecret()
	if err != nil {
		return errors.Wrap(err, "intializing node-exporter rbac proxy secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ctx, nes)
	if err != nil {
		return errors.Wrap(err, "creating node-exporter rbac proxy secret failed")
	}
	svc, err := t.factory.NodeExporterService()
	if err != nil {
		return errors.Wrap(err, "initializing node-exporter Service failed")
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "reconciling node-exporter Service failed")
	}

	ds, err := t.factory.NodeExporterDaemonSet()
	if err != nil {
		return errors.Wrap(err, "initializing node-exporter DaemonSet failed")
	}

	err = t.client.CreateOrUpdateDaemonSet(ctx, ds)
	if err != nil {
		return errors.Wrap(err, "reconciling node-exporter DaemonSet failed")
	}

	pr, err := t.factory.NodeExporterPrometheusRule()
	if err != nil {
		return errors.Wrap(err, "initializing node-exporter rules PrometheusRule failed")
	}
	err = t.client.CreateOrUpdatePrometheusRule(ctx, pr)
	if err != nil {
		return errors.Wrap(err, "reconciling node-exporter rules PrometheusRule failed")
	}

	smn, err := t.factory.NodeExporterServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing node-exporter ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smn)
	return errors.Wrap(err, "reconciling node-exporter ServiceMonitor failed")
}
