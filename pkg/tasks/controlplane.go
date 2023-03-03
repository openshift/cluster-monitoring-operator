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

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"

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
		return errors.Wrap(err, "initializing kubernetes mixin rules PrometheusRule failed")
	}
	err = t.client.CreateOrUpdatePrometheusRule(ctx, pr)
	if err != nil {
		return errors.Wrap(err, "reconciling kubernetes mixin rules PrometheusRule failed")
	}

	sms, err := t.factory.ControlPlaneKubeletServiceMonitors()
	if err != nil {
		return errors.Wrap(err, "initializing control-plane kubelet ServiceMonitors failed")
	}

	for _, sm := range sms {
		err = t.client.CreateOrUpdateServiceMonitor(ctx, sm)
		if err != nil {
			return errors.Wrapf(err, "reconciling %s/%s ServiceMonitor failed", sm.Namespace, sm.Name)
		}
	}

	smkpa, err := t.factory.ControlPlaneKubeletServiceMonitorPA()
	if err != nil {
		return errors.Wrap(err, "initializing prometheus-adapter dedicated kubelet ServiceMonitor failed")
	}

	if t.config.ClusterMonitoringConfiguration.K8sPrometheusAdapter.DedicatedServiceMonitors.Enabled {
		err = t.client.CreateOrUpdateServiceMonitor(ctx, smkpa)
		if err != nil {
			return errors.Wrap(err, "reconciling prometheus-adapter dedicated kubelet ServiceMonitor failed")
		}
	} else {
		err = t.client.DeleteServiceMonitor(ctx, smkpa)
		if err != nil {
			return errors.Wrap(err, "deleting prometheus-adapter dedicated kubelet ServiceMonitor failed")
		}
	}

	sms, err = t.factory.ControlPlaneEtcdServiceMonitors()
	if err != nil {
		return errors.Wrap(err, "initializing control-plane etcd ServiceMonitors failed")
	}

	if t.config.ClusterMonitoringConfiguration.EtcdConfig.IsEnabled() {
		for _, sm := range sms {
			err = t.client.CreateOrUpdateServiceMonitor(ctx, sm)
			if err != nil {
				return errors.Wrapf(err, "reconciling %s/%s ServiceMonitor failed", sm.Namespace, sm.Name)
			}
		}

		etcdCA, err := t.client.WaitForConfigMapByNsName(ctx, types.NamespacedName{Namespace: "openshift-config", Name: "etcd-metric-serving-ca"})
		if err != nil {
			return errors.Wrap(err, "failed to wait for openshift-config/etcd-metric-serving-ca configmap")
		}

		etcdClientSecret, err := t.client.WaitForSecretByNsName(ctx, types.NamespacedName{Namespace: "openshift-config", Name: "etcd-metric-client"})
		if err != nil {
			return errors.Wrap(err, "failed to wait for openshift-config/etcd-metric-client secret")
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
		for _, sm := range sms {
			err = t.client.DeleteServiceMonitor(ctx, sm)
			if err != nil {
				return errors.Wrapf(err, "deleting %s/%s ServiceMonitor failed", sm.Namespace, sm.Name)
			}
		}
	}

	return nil
}
