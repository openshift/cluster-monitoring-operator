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

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
	"k8s.io/klog/v2"
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
	cacm, err := t.factory.PrometheusK8sServingCertsCABundle()
	if err != nil {
		return errors.Wrap(err, "initializing serving certs CA Bundle ConfigMap failed")
	}

	_, err = t.client.CreateIfNotExistConfigMap(cacm)
	if err != nil {
		return errors.Wrap(err, "creating serving certs CA Bundle ConfigMap failed")
	}

	kscm, err := t.client.GetConfigmap("openshift-config-managed", "kubelet-serving-ca")
	if err != nil {
		return errors.Wrap(err, "openshift-config-managed/kubelet-serving-ca")
	}

	cacm, err = t.factory.PrometheusK8sKubeletServingCABundle(kscm.Data)
	if err != nil {
		return errors.Wrap(err, "initializing kubelet serving CA Bundle ConfigMap failed")
	}

	err = t.client.CreateOrUpdateConfigMap(cacm)
	if err != nil {
		return errors.Wrap(err, "creating kubelet serving CA Bundle ConfigMap failed")
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

	gs, err := t.factory.GrafanaDatasources()
	if err != nil {
		return errors.Wrap(err, "initializing Grafana Datasources Secret failed")
	}

	gs, err = t.client.WaitForSecret(gs)
	if err != nil {
		return errors.Wrap(err, "waiting for Grafana Datasources Secret failed")
	}

	d := &manifests.GrafanaDatasources{}
	err = json.Unmarshal(gs.Data["prometheus.yaml"], d)
	if err != nil {
		return errors.Wrap(err, "unmarshalling grafana datasource failed")
	}

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

	// TODO(paulfantom): Can be removed after OpenShift 4.7 and earlier are no longer supported
	err = t.client.DeletePrometheusRuleByNamespaceAndName(t.client.Namespace(), "prometheus-k8s-rules")
	if err != nil {
		return errors.Wrap(err, "removing old Prometheus rules PrometheusRule failed")
	}

	pm, err := t.factory.PrometheusK8sPrometheusRule()
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

	svc, err = t.factory.PrometheusK8sServiceThanosSidecar()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos sidecar Service failed")
	}

	err = t.client.CreateOrUpdateService(svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos sidecar Service failed")
	}

	grpcTLS, err := t.factory.GRPCSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus GRPC secret failed")
	}

	grpcTLS, err = t.client.WaitForSecret(grpcTLS)
	if err != nil {
		return errors.Wrap(err, "waiting for Prometheus GRPC secret failed")
	}

	s, err := t.factory.PrometheusK8sGrpcTLSSecret()
	if err != nil {
		return errors.Wrap(err, "error initializing Prometheus Client GRPC TLS secret")
	}

	s, err = t.factory.HashSecret(s,
		"ca.crt", string(grpcTLS.Data["ca.crt"]),
		"server.crt", string(grpcTLS.Data["prometheus-server.crt"]),
		"server.key", string(grpcTLS.Data["prometheus-server.key"]),
	)
	if err != nil {
		return errors.Wrap(err, "error hashing Prometheus Client GRPC TLS secret")
	}

	err = t.client.CreateOrUpdateSecret(s)
	if err != nil {
		return errors.Wrap(err, "error creating Prometheus Client GRPC TLS secret")
	}

	err = t.client.DeleteHashedSecret(
		s.GetNamespace(),
		"prometheus-k8s-grpc-tls",
		string(s.Labels["monitoring.openshift.io/hash"]),
	)
	if err != nil {
		return errors.Wrap(err, "error creating Prometheus Client GRPC TLS secret")
	}
	{
		pdb, err := t.factory.PrometheusK8sPodDisruptionBudget()
		if err != nil {
			return errors.Wrap(err, "initializing Prometheus PodDisruptionBudget object failed")
		}

		if pdb != nil {
			err = t.client.CreateOrUpdatePodDisruptionBudget(pdb)
			if err != nil {
				return errors.Wrap(err, "reconciling Prometheus PodDisruptionBudget object failed")
			}
		}
	}
	{
		// Create trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.PrometheusK8sTrustedCABundle()
		if err != nil {
			return errors.Wrap(err, "initializing Prometheus CA bundle ConfigMap failed")
		}

		cbs := &caBundleSyncer{
			client:  t.client,
			factory: t.factory,
			prefix:  "prometheus",
		}
		trustedCA, err = cbs.syncTrustedCABundle(trustedCA)
		if err != nil {
			return errors.Wrap(err, "syncing Prometheus trusted CA bundle ConfigMap failed")
		}

		klog.V(4).Info("initializing Prometheus object")
		p, err := t.factory.PrometheusK8s(host, s, trustedCA)
		if err != nil {
			return errors.Wrap(err, "initializing Prometheus object failed")
		}

		klog.V(4).Info("reconciling Prometheus object")
		err = t.client.CreateOrUpdatePrometheus(p)
		if err != nil {
			return errors.Wrap(err, "reconciling Prometheus object failed")
		}

		klog.V(4).Info("waiting for Prometheus object changes")
		err = t.client.WaitForPrometheus(p)
		if err != nil {
			return errors.Wrap(err, "waiting for Prometheus object changes failed")
		}
	}

	smp, err := t.factory.PrometheusK8sPrometheusServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Prometheus ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smp)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Prometheus ServiceMonitor failed")
	}

	smt, err := t.factory.PrometheusK8sThanosSidecarServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Thanos sidecar ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smt)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Thanos sidecar ServiceMonitor failed")
	}

	// Clean up the service monitors previously managed by the cluster monitoring operator.
	// TODO(bison): Verify these are no longer needed and remove them after 4.8 release.
	deprecatedServiceMonitors := []string{
		"cluster-version-operator",
		"kube-apiserver",
		"kube-controller-manager",
		"kube-scheduler",
		"openshift-apiserver",
		"prometheus", // Bug 1952744: Renamed to "prometheus-k8s" in #1044.
	}

	for _, name := range deprecatedServiceMonitors {
		err := t.client.DeleteServiceMonitorByNamespaceAndName(t.client.Namespace(), name)
		if err != nil {
			return errors.Wrapf(err, "deleting Prometheus %s ServiceMonitor failed", name)
		}
	}
	return nil
}
