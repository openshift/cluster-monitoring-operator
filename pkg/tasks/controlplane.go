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

type ControlPlaneTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewControlPlaneTask(client *client.Client, factory *manifests.Factory, config *manifests.Config) *ControlPlaneTask {
	return &ControlPlaneTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *ControlPlaneTask) Run(ctx context.Context) error {
	pr, err := t.factory.ControlPlanePrometheusRule()
	if err != nil {
		return fmt.Errorf("initializing kubernetes mixin rules PrometheusRule failed: %w", err)
	}
	err = t.client.CreateOrUpdatePrometheusRule(ctx, pr)
	if err != nil {
		return fmt.Errorf("reconciling kubernetes mixin rules PrometheusRule failed: %w", err)
	}

	sms, err := t.factory.ControlPlaneKubeletServiceMonitors()
	if err != nil {
		return fmt.Errorf("initializing control-plane kubelet ServiceMonitors failed: %w", err)
	}

	for _, sm := range sms {
		err = t.client.CreateOrUpdateServiceMonitor(ctx, sm)
		if err != nil {
			return fmt.Errorf("reconciling %s/%s ServiceMonitor failed: %w", sm.Namespace, sm.Name, err)
		}
	}

	return nil
}
