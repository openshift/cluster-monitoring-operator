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
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
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

func (t *OpenShiftStateMetricsTask) Run() error {
	sa, err := t.factory.OpenShiftStateMetricsServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing openshift-state-metrics Service failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(sa)
	if err != nil {
		return errors.Wrap(err, "reconciling openshift-state-metrics ServiceAccount failed")
	}

	cr, err := t.factory.OpenShiftStateMetricsClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing openshift-state-metrics ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "reconciling openshift-state-metrics ClusterRole failed")
	}

	crb, err := t.factory.OpenShiftStateMetricsClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing openshift-state-metrics ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "reconciling openshift-state-metrics ClusterRoleBinding failed")
	}

	svc, err := t.factory.OpenShiftStateMetricsService()
	if err != nil {
		return errors.Wrap(err, "initializing openshift-state-metrics Service failed")
	}

	err = t.client.CreateOrUpdateService(svc)
	if err != nil {
		return errors.Wrap(err, "reconciling openshift-state-metrics Service failed")
	}

	dep, err := t.factory.OpenShiftStateMetricsDeployment()
	if err != nil {
		return errors.Wrap(err, "initializing openshift-state-metrics Deployment failed")
	}

	err = t.client.CreateOrUpdateDeployment(dep)
	if err != nil {
		return errors.Wrap(err, "reconciling openshift-state-metrics Deployment failed")
	}

	sm, err := t.factory.OpenShiftStateMetricsServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing openshift-state-metrics ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(sm)
	return errors.Wrap(err, "reconciling openshift-state-metrics ServiceMonitor failed")
}
