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

type ClusterMonitoringOperatorTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewClusterMonitoringOperatorTask(client *client.Client, factory *manifests.Factory) *ClusterMonitoringOperatorTask {
	return &ClusterMonitoringOperatorTask{
		client:  client,
		factory: factory,
	}
}

func (t *ClusterMonitoringOperatorTask) Run() error {
	svc, err := t.factory.ClusterMonitoringOperatorService()
	if err != nil {
		return errors.Wrap(err, "initializing Cluster Monitoring Operator Service failed")
	}

	err = t.client.CreateOrUpdateService(svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Cluster Monitoring Operator Service failed")
	}

	cr, err := t.factory.ClusterMonitoringClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing cluster-monitoring ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "reconciling cluster-monitoring ClusterRole failed")
	}

	smcmo, err := t.factory.ClusterMonitoringOperatorServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Cluster Monitoring Operator ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smcmo)
	return errors.Wrap(err, "reconciling Cluster Monitoring Operator ServiceMonitor failed")
}
