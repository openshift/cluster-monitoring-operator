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
	"github.com/golang/glog"
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
)

type PrometheusTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewPrometheusTask(client *client.Client, factory *manifests.Factory) *PrometheusTask {
	return &PrometheusTask{
		client:  client,
		factory: factory,
	}
}

func (t *PrometheusTask) Run() error {
	r, err := t.factory.PrometheusK8sRoute()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Route failed")
	}

	err = t.client.CreateRouteIfNotExists(r)
	if err != nil {
		return errors.Wrap(err, "creating Prometheus Route failed")
	}

	host, err := t.client.WaitForRouteReady(r)
	if err != nil {
		return errors.Wrap(err, "waiting for Prometheus Route to become ready failed")
	}

	ps, err := t.factory.PrometheusK8sProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus proxy Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ps)
	if err != nil {
		return errors.Wrap(err, "creating Prometheus proxy Secret failed")
	}

	sa, err := t.factory.PrometheusK8sServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus ServiceAccount failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(sa)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus ServiceAccount failed")
	}

	cr, err := t.factory.PrometheusK8sClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus ClusterRole failed")
	}

	crb, err := t.factory.PrometheusK8sClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus ClusterRoleBinding failed")
	}

	rd, err := t.factory.PrometheusK8sRoleDefault()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Role default failed")
	}

	err = t.client.CreateOrUpdateRole(rd)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Role default failed")
	}

	rbd, err := t.factory.PrometheusK8sRoleBindingDefault()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus RoleBinding default failed")
	}

	err = t.client.CreateOrUpdateRoleBinding(rbd)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus RoleBinding default failed")
	}

	rks, err := t.factory.PrometheusK8sRoleKubeSystem()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Role kube-system failed")
	}

	err = t.client.CreateOrUpdateRole(rks)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Role kube-system failed")
	}

	rbks, err := t.factory.PrometheusK8sRoleBindingKubeSystem()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus RoleBinding kube-system failed")
	}

	err = t.client.CreateOrUpdateRoleBinding(rbks)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus RoleBinding kube-system failed")
	}

	rts, err := t.factory.PrometheusK8sRole()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Role failed")
	}

	err = t.client.CreateOrUpdateRole(rts)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Role failed")
	}

	rbts, err := t.factory.PrometheusK8sRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus RoleBinding failed")
	}

	err = t.client.CreateOrUpdateRoleBinding(rbts)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus RoleBinding failed")
	}

	cm, err := t.factory.PrometheusK8sRules()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus rules ConfigMap failed")
	}

	err = t.client.CreateOrUpdateConfigMap(cm)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus rules ConfigMap failed")
	}

	smk, err := t.factory.PrometheusK8sKubeletServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus kubelet ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smk)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus kubelet ServiceMonitor failed")
	}

	smn, err := t.factory.PrometheusK8sNodeExporterServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus node-exporter ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smn)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus node-exporter ServiceMonitor failed")
	}

	sma, err := t.factory.PrometheusK8sApiserverServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus apiserver ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(sma)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus apiserver ServiceMonitor failed")
	}

	smksm, err := t.factory.PrometheusK8sKubeStateMetricsServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus kube-state-metrics ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smksm)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus kube-state-metrics ServiceMonitor failed")
	}

	smam, err := t.factory.PrometheusK8sAlertmanagerServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Alertmanager ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smam)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Alertmanager ServiceMonitor failed")
	}

	smkc, err := t.factory.PrometheusK8sKubeControllersServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus kube-controllers ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smkc)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus kube-controllers ServiceMonitor failed")
	}

	smkd, err := t.factory.PrometheusK8sKubeDNSServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus kube-dns ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smkd)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus kube-dns ServiceMonitor failed")
	}

	smpo, err := t.factory.PrometheusK8sPrometheusOperatorServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Prometheus Operator ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smpo)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Prometheus Operator ServiceMonitor failed")
	}

	smp, err := t.factory.PrometheusK8sPrometheusServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Prometheus ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smp)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Prometheus ServiceMonitor failed")
	}

	aac, err := t.factory.PrometheusK8sAvailabilityAppCreateServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing availability-app-create ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(aac)
	if err != nil {
		return errors.Wrap(err, "reconciling availability-app-create ServiceMonitor failed")
	}

	svc, err := t.factory.PrometheusK8sService()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Service failed")
	}

	err = t.client.CreateOrUpdateService(svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Service failed")
	}

	kcmsvc, err := t.factory.KubeControllersService()
	if err != nil {
		return errors.Wrap(err, "initializing kube-controllers Service failed")
	}

	err = t.client.CreateOrUpdateService(kcmsvc)
	if err != nil {
		return errors.Wrap(err, "reconciling kube-controllers Service failed")
	}

	glog.V(4).Info("initializing Prometheus object")
	p, err := t.factory.PrometheusK8s(host)
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus object failed")
	}

	glog.V(4).Info("reconciling Prometheus object")
	err = t.client.CreateOrUpdatePrometheus(p)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus object failed")
	}

	glog.V(4).Info("waiting for Prometheus object changes")
	err = t.client.WaitForPrometheus(p)
	return errors.Wrap(err, "waiting for Prometheus object changes failed")
}
