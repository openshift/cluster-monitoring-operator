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

type NodeExporterDashboardTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewNodeExporterDashboardTask(client *client.Client, factory *manifests.Factory) *NodeExporterDashboardTask {
	return &NodeExporterDashboardTask{
		client:  client,
		factory: factory,
	}
}

func (t *NodeExporterDashboardTask) Run(ctx context.Context) error {
	dcm, err := t.factory.NodeExporterAcceleratorsDashboardConfigMap()
	if err != nil {
		return fmt.Errorf("initializing node-exporter accelerators dashboard ConfigMap failed: %w", err)
	}

	err = t.client.CreateOrUpdateConfigMap(ctx, dcm)
	if err != nil {
		return fmt.Errorf("reconciling node-exporter accelerators dashboard ConfigMap failed: %w", err)
	}

	return nil
}
