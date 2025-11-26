// Copyright 2025 The Cluster Monitoring Operator Authors
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

type DefaultDenyNetworkPolicyTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewDefaultDenyNetworkPolicyTask(client *client.Client, factory *manifests.Factory, config *manifests.Config) *DefaultDenyNetworkPolicyTask {
	return &DefaultDenyNetworkPolicyTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *DefaultDenyNetworkPolicyTask) Run(ctx context.Context) error {
	denyNetpol, err := t.factory.ClusterMonitoringDenyAllTraffic()
	if err != nil {
		return fmt.Errorf("initializing deny all pods traffic NetworkPolicy failed: %w", err)
	}

	err = t.client.CreateOrUpdateNetworkPolicy(ctx, denyNetpol)
	if err != nil {
		return fmt.Errorf("reconciling deny all pods traffic NetworkPolicy failed: %w", err)
	}

	return nil
}
