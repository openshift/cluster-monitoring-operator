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
	"k8s.io/klog/v2"
)

type PrometheusUserWorkloadTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewPrometheusUserWorkloadTask(client *client.Client, factory *manifests.Factory, config *manifests.Config) *PrometheusUserWorkloadTask {
	return &PrometheusUserWorkloadTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *PrometheusUserWorkloadTask) Run() error {
	if *t.config.ClusterMonitoringConfiguration.UserWorkloadEnabled {
		return t.create()
	}

	return t.destroy()
}

func (t *PrometheusUserWorkloadTask) create() error {
	cacm, err := t.factory.PrometheusUserWorkloadServingCertsCABundle()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload serving certs CA Bundle ConfigMap failed")
	}

	_, err = t.client.CreateIfNotExistConfigMap(cacm)
	if err != nil {
		return errors.Wrap(err, "creating UserWorkload serving certs CA Bundle ConfigMap failed")
	}

	sa, err := t.factory.PrometheusUserWorkloadServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ServiceAccount failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(sa)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus ServiceAccount failed")
	}

	cr, err := t.factory.PrometheusUserWorkloadClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus ClusterRole failed")
	}

	crb, err := t.factory.PrometheusUserWorkloadClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus ClusterRoleBinding failed")
	}

	rc, err := t.factory.PrometheusUserWorkloadRoleConfig()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Role config failed")
	}

	err = t.client.CreateOrUpdateRole(rc)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Role config failed")
	}

	rl, err := t.factory.PrometheusUserWorkloadRoleList()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Role failed")
	}

	for _, r := range rl.Items {
		err = t.client.CreateOrUpdateRole(&r)
		if err != nil {
			return errors.Wrapf(err, "reconciling UserWorkload Prometheus Role %q failed", r.Name)
		}
	}

	rbl, err := t.factory.PrometheusUserWorkloadRoleBindingList()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus RoleBinding failed")
	}

	for _, rb := range rbl.Items {
		err = t.client.CreateOrUpdateRoleBinding(&rb)
		if err != nil {
			return errors.Wrapf(err, "reconciling UserWorkload Prometheus RoleBinding %q failed", rb.Name)
		}
	}

	rbc, err := t.factory.PrometheusUserWorkloadRoleBindingConfig()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus config RoleBinding failed")
	}

	err = t.client.CreateOrUpdateRoleBinding(rbc)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus config RoleBinding failed")
	}

	svc, err := t.factory.PrometheusUserWorkloadService()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Service failed")
	}

	err = t.client.CreateOrUpdateService(svc)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Service failed")
	}

	svc, err = t.factory.PrometheusUserWorkloadServiceThanosSidecar()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Thanos sidecar Service failed")
	}

	err = t.client.CreateOrUpdateService(svc)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Thanos sidecar Service failed")
	}

	grpcTLS, err := t.factory.GRPCSecret()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus GRPC secret failed")
	}

	grpcTLS, err = t.client.WaitForSecret(grpcTLS)
	if err != nil {
		return errors.Wrap(err, "waiting for UserWorkload Prometheus GRPC secret failed")
	}

	s, err := t.factory.PrometheusUserWorkloadGrpcTLSSecret()
	if err != nil {
		return errors.Wrap(err, "error initializing UserWorkload Prometheus Client GRPC TLS secret")
	}

	s, err = t.factory.HashSecret(s,
		"ca.crt", string(grpcTLS.Data["ca.crt"]),
		"server.crt", string(grpcTLS.Data["prometheus-server.crt"]),
		"server.key", string(grpcTLS.Data["prometheus-server.key"]),
	)
	if err != nil {
		return errors.Wrap(err, "error hashing UserWorkload Prometheus Client GRPC TLS secret")
	}

	err = t.client.CreateOrUpdateSecret(s)
	if err != nil {
		return errors.Wrap(err, "error creating UserWorkload Prometheus Client GRPC TLS secret")
	}

	err = t.client.DeleteHashedSecret(
		s.GetNamespace(),
		"prometheus-user-workload-grpc-tls",
		string(s.Labels["monitoring.openshift.io/hash"]),
	)
	if err != nil {
		return errors.Wrap(err, "error creating UserWorkload Prometheus Client GRPC TLS secret")
	}
	{
		pdb, err := t.factory.PrometheusUserWorkloadPodDisruptionBudget()
		if err != nil {
			return errors.Wrap(err, "initializing UserWorkload Prometheus PodDisruptionBudget object failed")
		}

		if pdb != nil {
			err = t.client.CreateOrUpdatePodDisruptionBudget(pdb)
			if err != nil {
				return errors.Wrap(err, "reconciling UserWorkload Prometheus PodDisruptionBudget object failed")
			}
		}
	}

	klog.V(4).Info("initializing UserWorkload Prometheus object")
	p, err := t.factory.PrometheusUserWorkload(s)
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus object failed")
	}

	klog.V(4).Info("reconciling UserWorkload Prometheus object")
	err = t.client.CreateOrUpdatePrometheus(p)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus object failed")
	}

	klog.V(4).Info("waiting for UserWorkload Prometheus object changes")
	err = t.client.WaitForPrometheus(p)
	if err != nil {
		return errors.Wrap(err, "waiting for UserWorkload Prometheus object changes failed")
	}

	smp, err := t.factory.PrometheusUserWorkloadPrometheusServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smp)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus ServiceMonitor failed")
	}

	err = t.deleteDeprecatedServiceMonitors()
	if err != nil {
		return errors.Wrap(err, "deleting deprecated UserWorkload Prometheus ServiceMonitor failed")
	}

	smt, err := t.factory.PrometheusUserWorkloadThanosSidecarServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Thanos sidecar ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smt)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Thanos sidecar ServiceMonitor failed")
	}

	return nil
}

func (t *PrometheusUserWorkloadTask) destroy() error {
	smt, err := t.factory.PrometheusUserWorkloadThanosSidecarServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Thanos sidecar ServiceMonitor failed")
	}

	err = t.client.DeleteServiceMonitor(smt)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Thanos sidecar ServiceMonitor failed")
	}

	smp, err := t.factory.PrometheusUserWorkloadPrometheusServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ServiceMonitor failed")
	}

	err = t.client.DeleteServiceMonitor(smp)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus ServiceMonitor failed")
	}

	err = t.deleteDeprecatedServiceMonitors()
	if err != nil {
		return errors.Wrap(err, "deleting deprecated UserWorkload Prometheus ServiceMonitor failed")
	}

	grpcTLS, err := t.factory.GRPCSecret()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus GRPC secret failed")
	}

	grpcTLS, err = t.client.WaitForSecret(grpcTLS)
	if err != nil {
		return errors.Wrap(err, "waiting for UserWorkload Prometheus GRPC secret failed")
	}

	s, err := t.factory.PrometheusUserWorkloadGrpcTLSSecret()
	if err != nil {
		return errors.Wrap(err, "error initializing Prometheus Client GRPC TLS secret")
	}

	s, err = t.factory.HashSecret(s,
		"ca.crt", string(grpcTLS.Data["ca.crt"]),
		"server.crt", string(grpcTLS.Data["prometheus-server.crt"]),
		"server.key", string(grpcTLS.Data["prometheus-server.key"]),
	)

	p, err := t.factory.PrometheusUserWorkload(s)
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus object failed")
	}

	err = t.client.DeletePrometheus(p)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus object failed")
	}

	pdb, err := t.factory.PrometheusUserWorkloadPodDisruptionBudget()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus PodDisruptionBudget object failed")
	}

	if pdb != nil {
		err = t.client.DeletePodDisruptionBudget(pdb)
		if err != nil {
			return errors.Wrap(err, "deleting UserWorkload Prometheus PodDisruptionBudget object failed")
		}
	}

	err = t.client.DeleteSecret(s)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus TLS secret failed")
	}

	svc, err := t.factory.PrometheusUserWorkloadService()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Service failed")
	}

	err = t.client.DeleteService(svc)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Service failed")
	}

	svc, err = t.factory.PrometheusUserWorkloadServiceThanosSidecar()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Thanos sidecar Service failed")
	}

	err = t.client.DeleteService(svc)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Service failed")
	}

	rbc, err := t.factory.PrometheusUserWorkloadRoleBindingConfig()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus config RoleBinding failed")
	}

	err = t.client.DeleteRoleBinding(rbc)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Service failed")
	}

	rbl, err := t.factory.PrometheusUserWorkloadRoleBindingList()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus RoleBinding failed")
	}

	for _, rb := range rbl.Items {
		err = t.client.DeleteRoleBinding(&rb)
		if err != nil {
			return errors.Wrapf(err, "deleting UserWorkload Prometheus RoleBinding %q failed", rb.Name)
		}
	}

	rl, err := t.factory.PrometheusUserWorkloadRoleList()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Role failed")
	}

	for _, r := range rl.Items {
		err = t.client.DeleteRole(&r)
		if err != nil {
			return errors.Wrapf(err, "deleting UserWorkload Prometheus Role %q failed", r.Name)
		}
	}

	rc, err := t.factory.PrometheusUserWorkloadRoleConfig()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Role config failed")
	}

	err = t.client.DeleteRole(rc)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Role config failed")
	}

	crb, err := t.factory.PrometheusUserWorkloadClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ClusterRoleBinding failed")
	}

	err = t.client.DeleteClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus ClusterRoleBinding failed")
	}

	cr, err := t.factory.PrometheusUserWorkloadClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ClusterRole failed")
	}

	err = t.client.DeleteClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus ClusterRole failed")
	}

	sa, err := t.factory.PrometheusUserWorkloadServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ServiceAccount failed")
	}

	err = t.client.DeleteServiceAccount(sa)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus ServiceAccount failed")
	}

	cacm, err := t.factory.PrometheusUserWorkloadServingCertsCABundle()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload serving certs CA Bundle ConfigMap failed")
	}

	err = t.client.DeleteConfigMap(cacm)
	return errors.Wrap(err, "deleting UserWorkload serving certs CA Bundle ConfigMap failed")
}

func (t *PrometheusUserWorkloadTask) deleteDeprecatedServiceMonitors() error {
	// TODO(bison): This can be removed after the 4.8 release.  The "prometheus"
	// ServiceMonitor was renamed to "prometheus-user-workload" recently. See:
	//
	//   https://github.com/openshift/cluster-monitoring-operator/pull/1044
	//   https://bugzilla.redhat.com/show_bug.cgi?id=1959278
	//
	deprecatedServiceMonitors := []string{"prometheus"}

	for _, name := range deprecatedServiceMonitors {
		err := t.client.DeleteServiceMonitorByNamespaceAndName(t.client.UserWorkloadNamespace(), name)
		if err != nil {
			return err
		}
	}

	return nil
}
