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
	"encoding/json"

	"github.com/golang/glog"
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PrometheusTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewPrometheusTask(client *client.Client, factory *manifests.Factory, config *manifests.Config) *PrometheusTask {
	return &PrometheusTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *PrometheusTask) Run() error {
	cacm, err := t.factory.PrometheusK8sServingCertsCABundle()
	if err != nil {
		return errors.Wrap(err, "initializing serving certs CA Bundle ConfigMap failed")
	}

	err = t.client.CreateIfNotExistConfigMap(cacm)
	if err != nil {
		return errors.Wrap(err, "creating serving certs CA Bundle ConfigMap failed")
	}

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

	c := t.client.KubernetesInterface()
	cm, err := c.CoreV1().Secrets(t.client.Namespace()).Get("grafana-datasources", metav1.GetOptions{})
	if err != nil {
		return errors.Wrap(err, "failed to retrieve Grafana datasources config")
	}
	d := &manifests.GrafanaDatasources{}
	err = json.Unmarshal(cm.Data["prometheus.yaml"], d)

	hs, err := t.factory.PrometheusK8sHtpasswdSecret(d.Datasources[0].BasicAuthPassword)
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus htpasswd Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(hs)
	if err != nil {
		return errors.Wrap(err, "creating Prometheus htpasswd Secret failed")
	}

	rs, err := t.factory.PrometheusRBACProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus RBAC proxy Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(rs)
	if err != nil {
		return errors.Wrap(err, "creating Prometheus RBAC proxy Secret failed")
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

	rc, err := t.factory.PrometheusK8sRoleConfig()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Role config failed")
	}

	err = t.client.CreateOrUpdateRole(rc)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Role config failed")
	}

	rl, err := t.factory.PrometheusK8sRoleList()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Role failed")
	}

	for _, r := range rl.Items {
		err = t.client.CreateOrUpdateRole(&r)
		if err != nil {
			return errors.Wrapf(err, "reconciling Prometheus Role %q failed", r.Name)
		}
	}

	rbl, err := t.factory.PrometheusK8sRoleBindingList()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus RoleBinding failed")
	}

	for _, rb := range rbl.Items {
		err = t.client.CreateOrUpdateRoleBinding(&rb)
		if err != nil {
			return errors.Wrapf(err, "reconciling Prometheus RoleBinding %q failed", rb.Name)
		}
	}

	rbc, err := t.factory.PrometheusK8sRoleBindingConfig()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus config RoleBinding failed")
	}

	err = t.client.CreateOrUpdateRoleBinding(rbc)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus config RoleBinding failed")
	}

	pm, err := t.factory.PrometheusK8sRules()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus rules PrometheusRule failed")
	}

	err = t.client.CreateOrUpdatePrometheusRule(pm)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus rules PrometheusRule failed")
	}

	svc, err := t.factory.PrometheusK8sService()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Service failed")
	}

	err = t.client.CreateOrUpdateService(svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Service failed")
	}

	if t.config.EtcdConfig.IsEnabled() {
		etcdCA, err := t.client.GetConfigmap("openshift-config", "etcd-metric-serving-ca")
		if err != nil {
			return errors.Wrap(err, "failed to load etcd client CA")
		}

		etcdClientSecret, err := t.client.GetSecret("openshift-config", "etcd-metric-client")
		if err != nil {
			return errors.Wrap(err, "failed to load etcd client secret")
		}

		promEtcdSecret, err := t.factory.PrometheusK8sEtcdSecret(etcdClientSecret, etcdCA)
		if err != nil {
			return errors.Wrap(err, "initializing prometheus etcd service monitor secret failed")
		}

		err = t.client.CreateOrUpdateSecret(promEtcdSecret)
		if err != nil {
			return errors.Wrap(err, "reconciling prometheus etcd service monitor secret")
		}
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
	if err != nil {
		return errors.Wrap(err, "waiting for Prometheus object changes failed")
	}

	smks, err := t.factory.PrometheusK8sKubeSchedulerServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus kube-scheduler ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smks)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus kube-scheduler ServiceMonitor failed")
	}

	smcvo, err := t.factory.PrometheusK8sServiceMonitorClusterVersionOperator()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus cluster-version-operator ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smcvo)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus cluster-version-operator ServiceMonitor failed")
	}

	sme, err := t.factory.PrometheusK8sEtcdServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus etcd ServiceMonitor failed")
	}

	if t.config.EtcdConfig.IsEnabled() {
		err = t.client.CreateOrUpdateServiceMonitor(sme)
		if err != nil {
			return errors.Wrap(err, "reconciling Prometheus etcd ServiceMonitor failed")
		}
	} else {
		err = t.client.DeleteServiceMonitor(sme)
		if err != nil {
			return errors.Wrap(err, "deleting Prometheus etcd ServiceMonitor failed")
		}
	}

	smp, err := t.factory.PrometheusK8sPrometheusServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Prometheus ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smp)
	return errors.Wrap(err, "reconciling Prometheus Prometheus ServiceMonitor failed")
}
