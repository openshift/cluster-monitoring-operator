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
	"context"
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

func (t *PrometheusUserWorkloadTask) Run(ctx context.Context) error {
	if *t.config.ClusterMonitoringConfiguration.UserWorkloadEnabled {
		return t.create(ctx)
	}

	return t.destroy(ctx)
}

func (t *PrometheusUserWorkloadTask) create(ctx context.Context) error {
	cacm, err := t.factory.PrometheusUserWorkloadServingCertsCABundle()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload serving certs CA Bundle ConfigMap failed")
	}

	_, err = t.client.CreateIfNotExistConfigMap(ctx, cacm)
	if err != nil {
		return errors.Wrap(err, "creating UserWorkload serving certs CA Bundle ConfigMap failed")
	}

	sa, err := t.factory.PrometheusUserWorkloadServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ServiceAccount failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus ServiceAccount failed")
	}

	cr, err := t.factory.PrometheusUserWorkloadClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus ClusterRole failed")
	}

	crb, err := t.factory.PrometheusUserWorkloadClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus ClusterRoleBinding failed")
	}

	rc, err := t.factory.PrometheusUserWorkloadRoleConfig()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Role config failed")
	}

	err = t.client.CreateOrUpdateRole(ctx, rc)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Role config failed")
	}

	rl, err := t.factory.PrometheusUserWorkloadRoleList()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Role failed")
	}

	for _, r := range rl.Items {
		err = t.client.CreateOrUpdateRole(ctx, &r)
		if err != nil {
			return errors.Wrapf(err, "reconciling UserWorkload Prometheus Role %q failed", r.Name)
		}
	}

	rbl, err := t.factory.PrometheusUserWorkloadRoleBindingList()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus RoleBinding failed")
	}

	for _, rb := range rbl.Items {
		err = t.client.CreateOrUpdateRoleBinding(ctx, &rb)
		if err != nil {
			return errors.Wrapf(err, "reconciling UserWorkload Prometheus RoleBinding %q failed", rb.Name)
		}
	}

	rbc, err := t.factory.PrometheusUserWorkloadRoleBindingConfig()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus config RoleBinding failed")
	}

	err = t.client.CreateOrUpdateRoleBinding(ctx, rbc)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus config RoleBinding failed")
	}

	svc, err := t.factory.PrometheusUserWorkloadService()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Service failed")
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus Service failed")
	}

	svc, err = t.factory.PrometheusUserWorkloadServiceThanosSidecar()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Thanos sidecar Service failed")
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Thanos sidecar Service failed")
	}

	grpcTLS, err := t.factory.GRPCSecret()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus GRPC secret failed")
	}

	grpcTLS, err = t.client.WaitForSecret(ctx, grpcTLS)
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

	err = t.client.CreateOrUpdateSecret(ctx, s)
	if err != nil {
		return errors.Wrap(err, "error creating UserWorkload Prometheus Client GRPC TLS secret")
	}

	err = t.client.DeleteHashedSecret(
		ctx,
		s.GetNamespace(),
		"prometheus-user-workload-grpc-tls",
		string(s.Labels["monitoring.openshift.io/hash"]),
	)
	if err != nil {
		return errors.Wrap(err, "error creating UserWorkload Prometheus Client GRPC TLS secret")
	}

	rs, err := t.factory.PrometheusUserWorkloadRBACProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus RBAC proxy Secret failed")
	}

	err = t.client.CreateOrUpdateSecret(ctx, rs)
	if err != nil {
		return errors.Wrap(err, "creating or updating UserWorkload Prometheus RBAC proxy Secret failed")
	}

	secret, err := t.factory.PrometheusUserWorkloadAdditionalAlertManagerConfigsSecret()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus additionalAlertmanagerConfigs secret failed")
	}
	klog.V(4).Info("reconciling UserWorkload Prometheus additionalAlertmanagerConfigs secret")
	err = t.client.CreateOrUpdateSecret(ctx, secret)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus additionalAlertmanagerConfigs secret failed")
	}

	pdb, err := t.factory.PrometheusUserWorkloadPodDisruptionBudget()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus PodDisruptionBudget object failed")
	}

	if pdb != nil {
		err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb)
		if err != nil {
			return errors.Wrap(err, "reconciling UserWorkload Prometheus PodDisruptionBudget object failed")
		}
	}

	klog.V(4).Info("initializing UserWorkload Prometheus object")
	p, err := t.factory.PrometheusUserWorkload(s)
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus object failed")
	}

	klog.V(4).Info("reconciling UserWorkload Prometheus object")
	err = t.client.CreateOrUpdatePrometheus(ctx, p)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus object failed")
	}

	klog.V(4).Info("waiting for UserWorkload Prometheus object changes")
	err = t.client.WaitForPrometheus(ctx, p)
	if err != nil {
		return errors.Wrap(err, "waiting for UserWorkload Prometheus object changes failed")
	}

	smp, err := t.factory.PrometheusUserWorkloadPrometheusServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smp)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Prometheus ServiceMonitor failed")
	}

	smt, err := t.factory.PrometheusUserWorkloadThanosSidecarServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Thanos sidecar ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smt)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkload Thanos sidecar ServiceMonitor failed")
	}

	return nil
}

func (t *PrometheusUserWorkloadTask) destroy(ctx context.Context) error {
	smt, err := t.factory.PrometheusUserWorkloadThanosSidecarServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Thanos sidecar ServiceMonitor failed")
	}

	err = t.client.DeleteServiceMonitor(ctx, smt)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Thanos sidecar ServiceMonitor failed")
	}

	smp, err := t.factory.PrometheusUserWorkloadPrometheusServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ServiceMonitor failed")
	}

	err = t.client.DeleteServiceMonitor(ctx, smp)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus ServiceMonitor failed")
	}

	grpcTLS, err := t.factory.GRPCSecret()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus GRPC secret failed")
	}

	grpcTLS, err = t.client.WaitForSecret(ctx, grpcTLS)
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

	pdb, err := t.factory.PrometheusUserWorkloadPodDisruptionBudget()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus PodDisruptionBudget object failed")
	}

	if pdb != nil {
		err = t.client.DeletePodDisruptionBudget(ctx, pdb)
		if err != nil {
			return errors.Wrap(err, "deleting UserWorkload Prometheus PodDisruptionBudget object failed")
		}
	}

	p, err := t.factory.PrometheusUserWorkload(s)
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus object failed")
	}

	err = t.client.DeletePrometheus(ctx, p)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus object failed")
	}

	err = t.client.DeleteSecret(ctx, s)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus TLS secret failed")
	}

	svc, err := t.factory.PrometheusUserWorkloadService()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Service failed")
	}

	err = t.client.DeleteService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Service failed")
	}

	svc, err = t.factory.PrometheusUserWorkloadServiceThanosSidecar()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Thanos sidecar Service failed")
	}

	err = t.client.DeleteService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Service failed")
	}

	rbc, err := t.factory.PrometheusUserWorkloadRoleBindingConfig()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus config RoleBinding failed")
	}

	err = t.client.DeleteRoleBinding(ctx, rbc)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Service failed")
	}

	rbl, err := t.factory.PrometheusUserWorkloadRoleBindingList()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus RoleBinding failed")
	}

	for _, rb := range rbl.Items {
		err = t.client.DeleteRoleBinding(ctx, &rb)
		if err != nil {
			return errors.Wrapf(err, "deleting UserWorkload Prometheus RoleBinding %q failed", rb.Name)
		}
	}

	rl, err := t.factory.PrometheusUserWorkloadRoleList()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Role failed")
	}

	for _, r := range rl.Items {
		err = t.client.DeleteRole(ctx, &r)
		if err != nil {
			return errors.Wrapf(err, "deleting UserWorkload Prometheus Role %q failed", r.Name)
		}
	}

	rc, err := t.factory.PrometheusUserWorkloadRoleConfig()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus Role config failed")
	}

	err = t.client.DeleteRole(ctx, rc)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus Role config failed")
	}

	crb, err := t.factory.PrometheusUserWorkloadClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ClusterRoleBinding failed")
	}

	err = t.client.DeleteClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus ClusterRoleBinding failed")
	}

	cr, err := t.factory.PrometheusUserWorkloadClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ClusterRole failed")
	}

	err = t.client.DeleteClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus ClusterRole failed")
	}

	sa, err := t.factory.PrometheusUserWorkloadServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus ServiceAccount failed")
	}

	err = t.client.DeleteServiceAccount(ctx, sa)
	if err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus ServiceAccount failed")
	}

	cacm, err := t.factory.PrometheusUserWorkloadServingCertsCABundle()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload serving certs CA Bundle ConfigMap failed")
	}

	rs, err := t.factory.PrometheusUserWorkloadRBACProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus RBAC proxy Secret failed")
	}

	err = t.client.DeleteSecret(ctx, rs)
	if err != nil {
		return errors.Wrap(err, "deleting or updating UserWorkload Prometheus RBAC proxy Secret failed")
	}

	amsSecret, err := t.factory.PrometheusUserWorkloadAdditionalAlertManagerConfigsSecret()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Prometheus additionalAlertmanagerConfigs secret failed")
	}

	if err = t.client.DeleteSecret(ctx, amsSecret); err != nil {
		return errors.Wrap(err, "deleting UserWorkload Prometheus additionalAlertmanagerConfigs Secret failed")
	}

	err = t.client.DeleteConfigMap(ctx, cacm)
	return errors.Wrap(err, "deleting UserWorkload serving certs CA Bundle ConfigMap failed")
}
