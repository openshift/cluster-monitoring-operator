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
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
)

type ConfigSharingTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewConfigSharingTask(client *client.Client, factory *manifests.Factory) *ConfigSharingTask {
	return &ConfigSharingTask{
		client:  client,
		factory: factory,
	}
}

func (t *ConfigSharingTask) Run() error {
	promRoute, err := t.factory.PrometheusK8sRoute()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Route failed")
	}

	promHost, err := t.client.GetRouteHost(promRoute)
	if err != nil {
		return errors.Wrap(err, "failed to retrieve Prometheus host")
	}

	amRoute, err := t.factory.AlertmanagerRoute()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager Route failed")
	}

	amHost, err := t.client.GetRouteHost(amRoute)
	if err != nil {
		return errors.Wrap(err, "failed to retrieve Alertmanager host")
	}

	cm := t.factory.SharingConfig(promHost, amHost)
	err = t.client.CreateOrUpdateConfigMap(cm)
	if err != nil {
		return errors.Wrap(err, "reconciling Sharing Config ConfigMap failed")
	}

	return nil
}
