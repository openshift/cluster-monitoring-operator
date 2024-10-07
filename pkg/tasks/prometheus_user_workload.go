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
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
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
		return fmt.Errorf("initializing UserWorkload serving certs CA Bundle ConfigMap failed: %w", err)
	}

	_, err = t.client.CreateIfNotExistConfigMap(ctx, cacm)
	if err != nil {
		return fmt.Errorf("creating UserWorkload serving certs CA Bundle ConfigMap failed: %w", err)
	}

	sa, err := t.factory.PrometheusUserWorkloadServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus ServiceAccount failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus ServiceAccount failed: %w", err)
	}

	cr, err := t.factory.PrometheusUserWorkloadClusterRole()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus ClusterRole failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus ClusterRole failed: %w", err)
	}

	crb, err := t.factory.PrometheusUserWorkloadClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus ClusterRoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus ClusterRoleBinding failed: %w", err)
	}

	arl, err := t.factory.PrometheusUserWorkloadAlertmanagerUserWorkloadRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Alertmanager User Workload Role Binding failed: %w", err)
	}

	err = t.client.CreateOrUpdateRoleBinding(ctx, arl)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus Alertmanager User Workload Role Binding failed: %w", err)
	}

	rc, err := t.factory.PrometheusUserWorkloadRoleConfig()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Role config failed: %w", err)
	}

	err = t.client.CreateOrUpdateRole(ctx, rc)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus Role config failed: %w", err)
	}

	rl, err := t.factory.PrometheusUserWorkloadRoleList()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Role failed: %w", err)
	}

	for _, r := range rl.Items {
		err = t.client.CreateOrUpdateRole(ctx, &r)
		if err != nil {
			return fmt.Errorf("reconciling UserWorkload Prometheus Role %q failed: %w", r.Name, err)
		}
	}

	rbl, err := t.factory.PrometheusUserWorkloadRoleBindingList()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus RoleBinding failed: %w", err)
	}

	for _, rb := range rbl.Items {
		err = t.client.CreateOrUpdateRoleBinding(ctx, &rb)
		if err != nil {
			return fmt.Errorf("reconciling UserWorkload Prometheus RoleBinding %q failed: %w", rb.Name, err)
		}
	}

	rbc, err := t.factory.PrometheusUserWorkloadRoleBindingConfig()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus config RoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateRoleBinding(ctx, rbc)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus config RoleBinding failed: %w", err)
	}

	svc, err := t.factory.PrometheusUserWorkloadService()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus Service failed: %w", err)
	}

	svc, err = t.factory.PrometheusUserWorkloadServiceThanosSidecar()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Thanos sidecar Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Thanos sidecar Service failed: %w", err)
	}

	grpcTLS, err := t.factory.GRPCSecret()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus GRPC secret failed: %w", err)
	}

	grpcTLS, err = t.client.WaitForSecret(ctx, grpcTLS)
	if err != nil {
		return fmt.Errorf("waiting for UserWorkload Prometheus GRPC secret failed: %w", err)
	}

	s, err := t.factory.PrometheusUserWorkloadGrpcTLSSecret()
	if err != nil {
		return fmt.Errorf("error initializing UserWorkload Prometheus Client GRPC TLS secret: %w", err)
	}

	s, err = t.factory.HashSecret(s,
		"ca.crt", string(grpcTLS.Data["ca.crt"]),
		"server.crt", string(grpcTLS.Data["prometheus-server.crt"]),
		"server.key", string(grpcTLS.Data["prometheus-server.key"]),
	)
	if err != nil {
		return fmt.Errorf("error hashing UserWorkload Prometheus Client GRPC TLS secret: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("error creating UserWorkload Prometheus Client GRPC TLS secret: %w", err)
	}

	err = t.client.DeleteHashedSecret(
		ctx,
		s.GetNamespace(),
		"prometheus-user-workload-grpc-tls",
		s.Labels["monitoring.openshift.io/hash"],
	)
	if err != nil {
		return fmt.Errorf("error creating UserWorkload Prometheus Client GRPC TLS secret: %w", err)
	}

	rs, err := t.factory.PrometheusUserWorkloadRBACProxyMetricsSecret()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus RBAC proxy Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, rs)
	if err != nil {
		return fmt.Errorf("creating or updating UserWorkload Prometheus RBAC proxy Secret failed: %w", err)
	}

	fs, err := t.factory.PrometheusUserWorkloadRBACProxyFederateSecret()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus RBAC federate endpoint Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, fs)
	if err != nil {
		return fmt.Errorf("creating or updating UserWorkload Prometheus RBAC federate endpoint Secret failed: %w", err)
	}

	trustedCA, err := t.factory.PrometheusUserWorkloadTrustedCABundle()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload CA bundle ConfigMap failed: %w", err)
	}

	err = t.client.CreateOrUpdateConfigMap(ctx, trustedCA)
	if err != nil {
		return fmt.Errorf("creating or updating UserWorkload Prometheus CA bundle ConfigMap failed: %w", err)
	}

	secret, err := t.factory.PrometheusUserWorkloadAdditionalAlertManagerConfigsSecret()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus additionalAlertmanagerConfigs secret failed: %w", err)
	}
	klog.V(4).Info("reconciling UserWorkload Prometheus additionalAlertmanagerConfigs secret")
	err = t.client.CreateOrUpdateSecret(ctx, secret)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus additionalAlertmanagerConfigs secret failed: %w", err)
	}

	pdb, err := t.factory.PrometheusUserWorkloadPodDisruptionBudget()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus PodDisruptionBudget object failed: %w", err)
	}

	if pdb != nil {
		err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb)
		if err != nil {
			return fmt.Errorf("reconciling UserWorkload Prometheus PodDisruptionBudget object failed: %w", err)
		}
	}

	klog.V(4).Info("initializing UserWorkload Prometheus object")
	p, err := t.factory.PrometheusUserWorkload(s)
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus object failed: %w", err)
	}

	klog.V(4).Info("reconciling UserWorkload Prometheus object")
	_, err = t.client.CreateOrUpdatePrometheus(ctx, p)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus object failed: %w", err)
	}

	klog.V(4).Info("waiting for UserWorkload Prometheus object changes")
	err = t.client.ValidatePrometheus(ctx, types.NamespacedName{Namespace: p.Namespace, Name: p.Name})
	if err != nil {
		return fmt.Errorf("waiting for UserWorkload Prometheus object changes failed: %w", err)
	}

	smp, err := t.factory.PrometheusUserWorkloadPrometheusServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus ServiceMonitor failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smp)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Prometheus ServiceMonitor failed: %w", err)
	}

	smt, err := t.factory.PrometheusUserWorkloadThanosSidecarServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Thanos sidecar ServiceMonitor failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smt)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkload Thanos sidecar ServiceMonitor failed: %w", err)
	}

	hasRoutes, err := t.client.HasRouteCapability(ctx)
	if err != nil {
		return fmt.Errorf("checking for Route capability failed: %w", err)
	}
	if hasRoutes {
		r, err := t.factory.PrometheusUserWorkloadFederateRoute()
		if err != nil {
			return fmt.Errorf("initializing UserWorkload Prometheus federate Route failed: %w", err)
		}

		err = t.client.CreateOrUpdateRoute(ctx, r)
		if err != nil {
			return fmt.Errorf("reconciling UserWorkload federate Route failed: %w", err)
		}

		_, err = t.client.WaitForRouteReady(ctx, r)
		if err != nil {
			return fmt.Errorf("waiting for UserWorkload federate Route to become ready failed: %w", err)
		}
	}

	return nil
}

func (t *PrometheusUserWorkloadTask) destroy(ctx context.Context) error {
	smt, err := t.factory.PrometheusUserWorkloadThanosSidecarServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Thanos sidecar ServiceMonitor failed: %w", err)
	}

	err = t.client.DeleteServiceMonitor(ctx, smt)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Thanos sidecar ServiceMonitor failed: %w", err)
	}

	smp, err := t.factory.PrometheusUserWorkloadPrometheusServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus ServiceMonitor failed: %w", err)
	}

	err = t.client.DeleteServiceMonitor(ctx, smp)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus ServiceMonitor failed: %w", err)
	}

	grpcTLS, err := t.factory.GRPCSecret()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus GRPC secret failed: %w", err)
	}

	grpcTLS, err = t.client.WaitForSecret(ctx, grpcTLS)
	if err != nil {
		return fmt.Errorf("waiting for UserWorkload Prometheus GRPC secret failed: %w", err)
	}

	s, err := t.factory.PrometheusUserWorkloadGrpcTLSSecret()
	if err != nil {
		return fmt.Errorf("error initializing Prometheus Client GRPC TLS secret: %w", err)
	}

	s, err = t.factory.HashSecret(s,
		"ca.crt", string(grpcTLS.Data["ca.crt"]),
		"server.crt", string(grpcTLS.Data["prometheus-server.crt"]),
		"server.key", string(grpcTLS.Data["prometheus-server.key"]),
	)

	if err != nil {
		return fmt.Errorf("error hashing TLS secrets: %w", err)
	}

	pdb, err := t.factory.PrometheusUserWorkloadPodDisruptionBudget()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus PodDisruptionBudget object failed: %w", err)
	}

	if pdb != nil {
		err = t.client.DeletePodDisruptionBudget(ctx, pdb)
		if err != nil {
			return fmt.Errorf("deleting UserWorkload Prometheus PodDisruptionBudget object failed: %w", err)
		}
	}

	trustedCA, err := t.factory.PrometheusUserWorkloadTrustedCABundle()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload CA bundle ConfigMap failed: %w", err)
	}

	err = t.client.DeleteConfigMap(ctx, trustedCA)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload trusted CA Bundle ConfigMap failed: %w", err)
	}

	err = t.client.DeleteHashedConfigMap(ctx, trustedCA.GetNamespace(), "prometheus-user-workload", "")
	if err != nil {
		return fmt.Errorf("deleting UserWorkload trusted CA Bundle ConfigMap failed: %w", err)
	}

	p, err := t.factory.PrometheusUserWorkload(s)
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus object failed: %w", err)
	}

	err = t.client.DeletePrometheus(ctx, p)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus object failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus TLS secret failed: %w", err)
	}

	svc, err := t.factory.PrometheusUserWorkloadService()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Service failed: %w", err)
	}

	err = t.client.DeleteService(ctx, svc)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus Service failed: %w", err)
	}

	svc, err = t.factory.PrometheusUserWorkloadServiceThanosSidecar()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Thanos sidecar Service failed: %w", err)
	}

	err = t.client.DeleteService(ctx, svc)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus Service failed: %w", err)
	}

	rbc, err := t.factory.PrometheusUserWorkloadRoleBindingConfig()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus config RoleBinding failed: %w", err)
	}

	err = t.client.DeleteRoleBinding(ctx, rbc)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus Service failed: %w", err)
	}

	rbl, err := t.factory.PrometheusUserWorkloadRoleBindingList()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus RoleBinding failed: %w", err)
	}

	for _, rb := range rbl.Items {
		err = t.client.DeleteRoleBinding(ctx, &rb)
		if err != nil {
			return fmt.Errorf("deleting UserWorkload Prometheus RoleBinding %q failed: %w", rb.Name, err)
		}
	}

	rl, err := t.factory.PrometheusUserWorkloadRoleList()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Role failed: %w", err)
	}

	for _, r := range rl.Items {
		err = t.client.DeleteRole(ctx, &r)
		if err != nil {
			return fmt.Errorf("deleting UserWorkload Prometheus Role %q failed: %w", r.Name, err)
		}
	}

	rc, err := t.factory.PrometheusUserWorkloadRoleConfig()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus Role config failed: %w", err)
	}

	err = t.client.DeleteRole(ctx, rc)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus Role config failed: %w", err)
	}

	crb, err := t.factory.PrometheusUserWorkloadClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus ClusterRoleBinding failed: %w", err)
	}

	err = t.client.DeleteClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus ClusterRoleBinding failed: %w", err)
	}

	cr, err := t.factory.PrometheusUserWorkloadClusterRole()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus ClusterRole failed: %w", err)
	}

	err = t.client.DeleteClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus ClusterRole failed: %w", err)
	}

	sa, err := t.factory.PrometheusUserWorkloadServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus ServiceAccount failed: %w", err)
	}

	err = t.client.DeleteServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus ServiceAccount failed: %w", err)
	}

	cacm, err := t.factory.PrometheusUserWorkloadServingCertsCABundle()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload serving certs CA Bundle ConfigMap failed: %w", err)
	}

	rs, err := t.factory.PrometheusUserWorkloadRBACProxyMetricsSecret()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus RBAC proxy Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, rs)
	if err != nil {
		return fmt.Errorf("deleting or updating UserWorkload Prometheus RBAC proxy Secret failed: %w", err)
	}

	fs, err := t.factory.PrometheusUserWorkloadRBACProxyFederateSecret()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus RBAC federate endpoint Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, fs)
	if err != nil {
		return fmt.Errorf("deleting or updating UserWorkload Prometheus RBAC federate endpoint Secret failed: %w", err)
	}

	amsSecret, err := t.factory.PrometheusUserWorkloadAdditionalAlertManagerConfigsSecret()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus additionalAlertmanagerConfigs secret failed: %w", err)
	}

	if err = t.client.DeleteSecret(ctx, amsSecret); err != nil {
		return fmt.Errorf("deleting UserWorkload Prometheus additionalAlertmanagerConfigs Secret failed: %w", err)
	}

	err = t.client.DeleteConfigMap(ctx, cacm)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload serving certs CA Bundle ConfigMap failed: %w", err)
	}

	r, err := t.factory.PrometheusUserWorkloadFederateRoute()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Prometheus federate Route failed: %w", err)
	}

	err = t.client.DeleteRoute(ctx, r)
	if err != nil {
		return fmt.Errorf("deleting UserWorkload federate Route failed: %w", err)
	}
	return nil
}
