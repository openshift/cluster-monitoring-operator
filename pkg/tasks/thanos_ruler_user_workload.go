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
	"fmt"

	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

type ThanosRulerUserWorkloadTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewThanosRulerUserWorkloadTask(client *client.Client, factory *manifests.Factory, config *manifests.Config) *ThanosRulerUserWorkloadTask {
	return &ThanosRulerUserWorkloadTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *ThanosRulerUserWorkloadTask) Run(ctx context.Context) error {
	if *t.config.ClusterMonitoringConfiguration.UserWorkloadEnabled {
		return t.create(ctx)
	}

	klog.V(3).Infof("UWM thanos ruler is disabled (because UWM is disabled), existing related resources are to be destroyed.")
	return t.destroy(ctx)
}

func (t *ThanosRulerUserWorkloadTask) create(ctx context.Context) error {
	netpol, err := t.factory.ThanosRulerNetworkPolicy()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler NetworkPolicy failed: %w", err)
	}

	err = t.client.CreateOrUpdateNetworkPolicy(ctx, netpol)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Ruler NetworkPolicy failed: %w", err)
	}

	svc, err := t.factory.ThanosRulerService()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Ruler Service failed: %w", err)
	}

	hasRoutes, err := t.client.HasRouteCapability(ctx)
	if err != nil {
		return fmt.Errorf("checking for Route capability failed: %w", err)
	}
	if hasRoutes {
		r, err := t.factory.ThanosRulerRoute()
		if err != nil {
			return fmt.Errorf("initializing Thanos Ruler Route failed: %w", err)
		}

		err = t.client.CreateOrUpdateRoute(ctx, r)
		if err != nil {
			return fmt.Errorf("reconciling Thanos Ruler Route failed: %w", err)
		}

		_, err = t.client.WaitForRouteReady(ctx, r)
		if err != nil {
			return fmt.Errorf("waiting for Thanos Ruler Route to become ready failed: %w", err)
		}
	}

	cr, err := t.factory.ThanosRulerClusterRole()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler ClusterRole failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Ruler ClusterRole failed: %w", err)
	}

	crb, err := t.factory.ThanosRulerClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler ClusterRoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Ruler ClusterRoleBinding failed: %w", err)
	}

	moncrb, err := t.factory.ThanosRulerMonitoringClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler monitoring ClusterRoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, moncrb)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Ruler monitoring ClusterRoleBinding failed: %w", err)
	}

	monauwrl, err := t.factory.ThanosRulerMonitoringAlertmanagerUserWorkloadRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler monitoring Alertmanager User Workload Role Binding failed: %w", err)
	}

	err = t.client.CreateOrUpdateRoleBinding(ctx, monauwrl)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Ruler Alertmanager User Workload Role Binding failed: %w", err)
	}

	sa, err := t.factory.ThanosRulerServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler ServiceAccount failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Ruler ServiceAccount failed: %w", err)
	}

	s, err := t.factory.ThanosRulerRBACProxyWebSecret()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler kube-rbac-proxy web Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("creating Thanos Ruler kube-rbac-proxy web Secret failed: %w", err)
	}

	s, err = t.factory.ThanosRulerRBACProxyMetricsSecret()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler kube-rbac-proxy metrics Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("creating Thanos Ruler kube-rbac-proxy metrics Secret failed: %w", err)
	}

	// Thanos' components use https://godoc.org/github.com/prometheus/common/config#NewClientFromConfig
	// under the hood and the returned http.Client detects whenever the certificates are rotated,
	// so there is no need for us to rotate the CA.
	qcs, err := t.factory.ThanosRulerQueryConfigSecret()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler query config Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, qcs)
	if err != nil {
		return fmt.Errorf("creating Thanos Ruler query config Secret failed: %w", err)
	}

	// Thanos' components use https://godoc.org/github.com/prometheus/common/config#NewClientFromConfig
	// under the hood and the returned http.Client detects whenever the certificates are rotated,
	// so there is no need for us to rotate the CA.
	acs, err := t.factory.ThanosRulerAlertmanagerConfigSecret()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler Alertmanager config Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, acs)

	if err != nil {
		return fmt.Errorf("creating or updating Thanos Ruler alertmanager config Secret failed: %w", err)
	}

	{
		grpcTLS, err := t.factory.GRPCSecret()
		if err != nil {
			return fmt.Errorf("initializing UserWorkload Thanos Ruler GRPC secret failed: %w", err)
		}

		grpcTLS, err = t.client.WaitForSecret(ctx, grpcTLS)
		if err != nil {
			return fmt.Errorf("waiting for UserWorkload Thanos Ruler GRPC secret failed: %w", err)
		}

		grpcSecret, err := t.factory.ThanosRulerGrpcTLSSecret()
		if err != nil {
			return fmt.Errorf("error initializing UserWorkload Thanos Ruler GRPC TLS secret: %w", err)
		}

		grpcSecret, err = t.factory.HashSecret(grpcSecret,
			"ca.crt", string(grpcTLS.Data["ca.crt"]),
			"server.crt", string(grpcTLS.Data["prometheus-server.crt"]),
			"server.key", string(grpcTLS.Data["prometheus-server.key"]),
		)
		if err != nil {
			return fmt.Errorf("error hashing UserWorkload Thanos Ruler GRPC TLS secret: %w", err)
		}

		err = t.client.CreateOrUpdateSecret(ctx, grpcSecret)
		if err != nil {
			return fmt.Errorf("error creating UserWorkload Thanos Ruler GRPC TLS secret: %w", err)
		}

		err = t.client.DeleteHashedSecret(
			ctx,
			grpcSecret.GetNamespace(),
			"thanos-ruler-grpc-tls",
			grpcSecret.Labels["monitoring.openshift.io/hash"],
		)
		if err != nil {
			return fmt.Errorf("error deleting expired UserWorkload Thanos Ruler GRPC TLS secret: %w", err)
		}

		pdb, err := t.factory.ThanosRulerPodDisruptionBudget()
		if err != nil {
			return fmt.Errorf("initializing Thanos Ruler PodDisruptionBudget object failed: %w", err)
		}

		if pdb != nil {
			err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb)
			if err != nil {
				return fmt.Errorf("reconciling Thanos Ruler PodDisruptionBudget object failed: %w", err)
			}
		}

		tr, err := t.factory.ThanosRulerCustomResource(grpcSecret, acs)
		if err != nil {
			return fmt.Errorf("initializing ThanosRuler object failed: %w", err)
		}

		err = t.client.CreateOrUpdateThanosRuler(ctx, tr)
		if err != nil {
			return fmt.Errorf("reconciling ThanosRuler object failed: %w", err)
		}

		err = t.client.WaitForThanosRuler(ctx, tr)
		if err != nil {
			return fmt.Errorf("waiting for ThanosRuler object changes failed: %w", err)
		}
	}

	trsm, err := t.factory.ThanosRulerServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler ServiceMonitor failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, trsm)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Ruler ServiceMonitor failed: %w", err)
	}

	pm, err := t.factory.ThanosRulerPrometheusRule()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler PrometheusRule failed: %w", err)
	}
	err = t.client.CreateOrUpdatePrometheusRule(ctx, pm)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Ruler PrometheusRule failed: %w", err)
	}

	tramrb, err := t.factory.ThanosRulerAlertManagerRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler Alertmanager Role Binding failed: %w", err)
	}

	if t.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.IsEnabled() {
		if err = t.client.CreateOrUpdateRoleBinding(ctx, tramrb); err != nil {
			return fmt.Errorf("reconciling Thanos Ruler Alertmanager Role Binding failed: %w", err)
		}
	} else {
		if err = t.client.DeleteRoleBinding(ctx, tramrb); err != nil {
			return fmt.Errorf("deleting Thanos Ruler Alertmanager Role Binding failed: %w", err)
		}
	}

	return nil
}

func (t *ThanosRulerUserWorkloadTask) destroy(ctx context.Context) error {
	prmrl, err := t.factory.ThanosRulerPrometheusRule()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler PrometheusRule failed: %w", err)
	}

	err = t.client.DeletePrometheusRule(ctx, prmrl)
	if err != nil {
		return fmt.Errorf("deleting Thanos Ruler PrometheusRule failed: %w", err)
	}

	route, err := t.factory.ThanosRulerRoute()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler Route failed: %w", err)
	}

	err = t.client.DeleteRoute(ctx, route)
	if err != nil {
		return fmt.Errorf("deleting Thanos Ruler Route failed: %w", err)
	}

	svc, err := t.factory.ThanosRulerService()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler Service failed: %w", err)
	}

	err = t.client.DeleteService(ctx, svc)
	if err != nil {
		return fmt.Errorf("deleting Thanos Ruler Service failed: %w", err)
	}

	cr, err := t.factory.ThanosRulerClusterRole()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler ClusterRole failed: %w", err)
	}

	err = t.client.DeleteClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("deleting Thanos Ruler ClusterRole failed: %w", err)
	}

	crb, err := t.factory.ThanosRulerClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler ClusterRoleBinding failed: %w", err)
	}

	err = t.client.DeleteClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("deleting Thanos Ruler ClusterRoleBinding failed: %w", err)
	}

	sa, err := t.factory.ThanosRulerServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler ServiceAccount failed: %w", err)
	}

	err = t.client.DeleteServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("deleting Thanos Ruler ServiceAccount failed: %w", err)
	}

	tramrb, err := t.factory.ThanosRulerAlertManagerRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler Alertmanager Role Binding failed: %w", err)
	}

	err = t.client.DeleteRoleBinding(ctx, tramrb)
	if err != nil {
		return fmt.Errorf("deleting Thanos Ruler Alertmanager Role Binding failed: %w", err)
	}

	grpcTLS, err := t.factory.GRPCSecret()
	if err != nil {
		return fmt.Errorf("initializing UserWorkload Thanos Ruler GRPC secret failed: %w", err)
	}

	grpcTLS, err = t.client.WaitForSecret(ctx, grpcTLS)
	if err != nil {
		return fmt.Errorf("waiting for UserWorkload Thanos Ruler GRPC secret failed: %w", err)
	}

	grpcSecret, err := t.factory.ThanosRulerGrpcTLSSecret()
	if err != nil {
		return fmt.Errorf("error initializing UserWorkload Thanos Ruler GRPC TLS secret: %w", err)
	}

	grpcSecret, err = t.factory.HashSecret(grpcSecret,
		"ca.crt", string(grpcTLS.Data["ca.crt"]),
		"server.crt", string(grpcTLS.Data["prometheus-server.crt"]),
		"server.key", string(grpcTLS.Data["prometheus-server.key"]),
	)
	if err != nil {
		return fmt.Errorf("error hashing UserWorkload Thanos Ruler GRPC TLS secret: %w", err)
	}

	pdb, err := t.factory.ThanosRulerPodDisruptionBudget()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler PodDisruptionBudget object failed: %w", err)
	}

	if pdb != nil {
		err = t.client.DeletePodDisruptionBudget(ctx, pdb)
		if err != nil {
			return fmt.Errorf("deleting Thanos Ruler PodDisruptionBudget object failed: %w", err)
		}
	}

	acs, err := t.factory.ThanosRulerAlertmanagerConfigSecret()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler Alertmanager config Secret failed: %w", err)
	}

	tr, err := t.factory.ThanosRulerCustomResource(grpcSecret, acs)
	if err != nil {
		return fmt.Errorf("initializing ThanosRuler object failed: %w", err)
	}

	err = t.client.DeleteThanosRuler(ctx, tr)
	if err != nil {
		return fmt.Errorf("deleting ThanosRuler object failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, acs)
	if err != nil {
		return fmt.Errorf("deleting Thanos Ruler alertmanager config Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, grpcSecret)
	if err != nil {
		return fmt.Errorf("error deleting UserWorkload Thanos Ruler GRPC TLS secret: %w", err)
	}

	qcs, err := t.factory.ThanosRulerQueryConfigSecret()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler query config Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, qcs)
	if err != nil {
		return fmt.Errorf("deleting Thanos Ruler query config Secret failed: %w", err)
	}

	s, err := t.factory.ThanosRulerRBACProxyWebSecret()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler kube-rbac-proxy web Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("deleting Thanos Ruler kube-rbac-proxy web Secret failed: %w", err)
	}

	s, err = t.factory.ThanosRulerRBACProxyMetricsSecret()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler kube-rbac-proxy metrics Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("deleting Thanos Ruler kube-rbac-proxy metrics Secret failed: %w", err)
	}

	trsm, err := t.factory.ThanosRulerServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler ServiceMonitor failed: %w", err)
	}

	err = t.client.DeleteServiceMonitor(ctx, trsm)
	if err != nil {
		return fmt.Errorf("deleting Thanos Ruler ServiceMonitor failed: %w", err)
	}

	netpol, err := t.factory.ThanosRulerNetworkPolicy()
	if err != nil {
		return fmt.Errorf("initializing Thanos Ruler NetworkPolicy failed: %w", err)
	}

	err = t.client.DeleteNetworkPolicy(ctx, netpol)
	if err != nil {
		return fmt.Errorf("deleting Thanos Ruler NetworkPolicy failed: %w", err)
	}

	return nil
}
