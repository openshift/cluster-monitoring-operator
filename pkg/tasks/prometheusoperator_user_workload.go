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

type PrometheusOperatorUserWorkloadTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewPrometheusOperatorUserWorkloadTask(client *client.Client, factory *manifests.Factory, config *manifests.Config) *PrometheusOperatorUserWorkloadTask {
	return &PrometheusOperatorUserWorkloadTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *PrometheusOperatorUserWorkloadTask) Run() error {
	if *t.config.ClusterMonitoringConfiguration.UserWorkloadEnabled {
		return t.create()
	}

	return t.destroy()
}

func (t *PrometheusOperatorUserWorkloadTask) create() error {
	sa, err := t.factory.PrometheusOperatorUserWorkloadServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ServiceAccount failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(sa)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Operator ServiceAccount failed")
	}

	cr, err := t.factory.PrometheusOperatorUserWorkloadClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Operator ClusterRole failed")
	}

	crb, err := t.factory.PrometheusOperatorUserWorkloadClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Operator ClusterRoleBinding failed")
	}

	svc, err := t.factory.PrometheusOperatorUserWorkloadService()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator Service failed")
	}

	err = t.client.CreateOrUpdateService(svc)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Operator Service failed")
	}

	d, err := t.factory.PrometheusOperatorUserWorkloadDeployment()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator Deployment failed")
	}

	err = t.client.CreateOrUpdateDeployment(d)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Operator Deployment failed")
	}

	// The CRs will be created externally,
	// but we still have to wait for them here.
	err = t.client.AssurePrometheusOperatorCRsExist()
	if err != nil {
		return errors.Wrap(err, "waiting for Prometheus Operator CRs to become available failed")
	}

	smpo, err := t.factory.PrometheusOperatorUserWorkloadServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smpo)
	return errors.Wrap(err, "reconciling UserWorkload Prometheus Operator ServiceMonitor failed")
}

func (t *PrometheusOperatorUserWorkloadTask) destroy() error {
	dep, err := t.factory.PrometheusOperatorUserWorkloadDeployment()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator Deployment failed")
	}

	err = t.client.DeleteDeployment(dep)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Operator Deployment failed")
	}

	sm, err := t.factory.PrometheusOperatorUserWorkloadServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ServiceMonitor failed")
	}

	err = t.client.DeleteServiceMonitor(sm)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Operator ServiceMonitor failed")
	}

	svc, err := t.factory.PrometheusOperatorUserWorkloadService()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator Service failed")
	}

	err = t.client.DeleteService(svc)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Operator Service failed")
	}

	crb, err := t.factory.PrometheusOperatorUserWorkloadClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ClusterRoleBinding failed")
	}

	err = t.client.DeleteClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Operator ClusterRoleBinding failed")
	}

	cr, err := t.factory.PrometheusOperatorUserWorkloadClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ClusterRole failed")
	}

	err = t.client.DeleteClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Operator ClusterRoleBinding failed")
	}

	sa, err := t.factory.PrometheusOperatorUserWorkloadServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Operator ServiceAccount failed")
	}

	err = t.client.DeleteServiceAccount(sa)
	return errors.Wrap(err, "deleting Telemeter client ServiceAccount failed")
}
