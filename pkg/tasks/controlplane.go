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
		return errors.Wrap(err, "initializing kubernetes mixin rules PrometheusRule failed")
	}
	err = t.client.CreateOrUpdatePrometheusRule(ctx, pr)
	if err != nil {
		return errors.Wrap(err, "reconciling kubernetes mixin rules PrometheusRule failed")
	}

	smk, err := t.factory.ControlPlaneKubeletServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing control-plane kubelet ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smk)
	if err != nil {
		return errors.Wrap(err, "reconciling control-plane kubelet ServiceMonitor failed")
	}

	smkpa, err := t.factory.ControlPlaneKubeletServiceMonitorPA()
	if err != nil {
		return errors.Wrap(err, "initializing prometheus-adapater dedicated control-plane kubelet ServiceMonitor failed")
	}

	if *t.config.ClusterMonitoringConfiguration.K8sPrometheusAdapter.DedicatedServiceMonitors.Enabled {
		err = t.client.CreateOrUpdateServiceMonitor(ctx, smkpa)
		if err != nil {
			return errors.Wrap(err, "reconcilin prometheus-adapater dedicatedg control-plane kubelet ServiceMonitor failed")
		}
	} else {
		err = t.client.DeleteServiceMonitor(ctx, smkpa)
		if err != nil {
			return errors.Wrap(err, "deleting prometheus-adapater dedicated control-plane etcd ServiceMonitor failed")
		}
	}

	sme, err := t.factory.ControlPlaneEtcdServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing control-plane etcd ServiceMonitor failed")
	}

	if t.config.ClusterMonitoringConfiguration.EtcdConfig.IsEnabled() {
		err = t.client.CreateOrUpdateServiceMonitor(ctx, sme)
		if err != nil {
			return errors.Wrap(err, "reconciling control-plane etcd ServiceMonitor failed")
		}
		etcdCA, err := t.client.GetConfigmap(ctx, "openshift-config", "etcd-metric-serving-ca")
		if err != nil {
			return errors.Wrap(err, "failed to load etcd client CA")
		}

		etcdClientSecret, err := t.client.GetSecret(ctx, "openshift-config", "etcd-metric-client")
		if err != nil {
			return errors.Wrap(err, "failed to load etcd client secret")
		}

		promEtcdSecret, err := t.factory.ControlPlaneEtcdSecret(etcdClientSecret, etcdCA)
		if err != nil {
			return errors.Wrap(err, "initializing prometheus etcd service monitor secret failed")
		}

		err = t.client.CreateOrUpdateSecret(ctx, promEtcdSecret)
		if err != nil {
			return errors.Wrap(err, "reconciling prometheus etcd service monitor secret")
		}
	} else {
		err = t.client.DeleteServiceMonitor(ctx, sme)
		if err != nil {
			return errors.Wrap(err, "deleting control-plane etcd ServiceMonitor failed")
		}
	}

	return nil
}
