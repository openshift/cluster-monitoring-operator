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

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

type ThanosQuerierTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewThanosQuerierTask(client *client.Client, factory *manifests.Factory, cfg *manifests.Config) *ThanosQuerierTask {
	return &ThanosQuerierTask{
		client:  client,
		factory: factory,
		config:  cfg,
	}
}

func (t *ThanosQuerierTask) Run(ctx context.Context) error {
	svc, err := t.factory.ThanosQuerierService()
	if err != nil {
		return fmt.Errorf("initializing Thanos Querier Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Querier Service failed: %w", err)
	}

	hasRoutes, err := t.client.HasRouteCapability(ctx)
	if err != nil {
		return fmt.Errorf("checking for Route capability failed: %w", err)
	}
	if hasRoutes {
		r, err := t.factory.ThanosQuerierRoute()
		if err != nil {
			return fmt.Errorf("initializing Thanos Querier Route failed: %w", err)
		}

		err = t.client.CreateOrUpdateRoute(ctx, r)
		if err != nil {
			return fmt.Errorf("reconciling Thanos Querier Route failed: %w", err)
		}

		_, err = t.client.WaitForRouteReady(ctx, r)
		if err != nil {
			return fmt.Errorf("waiting for Thanos Querier Route to become ready failed: %w", err)
		}
	}

	rs, err := t.factory.ThanosQuerierRBACProxySecret()
	if err != nil {
		return fmt.Errorf("initializing Thanos Querier RBAC proxy Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, rs)
	if err != nil {
		return fmt.Errorf("creating Thanos Querier RBAC proxy Secret failed: %w", err)
	}

	rs, err = t.factory.ThanosQuerierRBACProxyRulesSecret()
	if err != nil {
		return fmt.Errorf("initializing Thanos Querier RBAC proxy rules Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, rs)
	if err != nil {
		return fmt.Errorf("creating Thanos Querier RBAC proxy rules Secret failed: %w", err)
	}

	rs, err = t.factory.ThanosQuerierRBACProxyMetricsSecret()
	if err != nil {
		return fmt.Errorf("initializing Thanos Querier RBAC proxy metrics Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, rs)
	if err != nil {
		return fmt.Errorf("creating Thanos Querier RBAC proxy metrics Secret failed: %w", err)
	}

	rs, err = t.factory.ThanosQuerierRBACProxyWebSecret()
	if err != nil {
		return fmt.Errorf("initializing Thanos Querier RBAC proxy web Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, rs)
	if err != nil {
		return fmt.Errorf("creating Thanos Querier kube-rbac-proxy web Secret failed: %w", err)
	}

	sa, err := t.factory.ThanosQuerierServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing Thanos Querier ServiceAccount failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Querier ServiceAccount failed: %w", err)
	}

	cr, err := t.factory.ThanosQuerierClusterRole()
	if err != nil {
		return fmt.Errorf("initializing Thanos Querier ClusterRole failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Querier ClusterRole failed: %w", err)
	}

	crb, err := t.factory.ThanosQuerierClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Thanos Querier ClusterRoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Querier ClusterRoleBinding failed: %w", err)
	}

	grpcTLS, err := t.factory.GRPCSecret()
	if err != nil {
		return fmt.Errorf("initializing Thanos Querier GRPC secret failed: %w", err)
	}

	grpcTLS, err = t.client.WaitForSecret(ctx, grpcTLS)
	if err != nil {
		return fmt.Errorf("waiting for Thanos Querier GRPC secret failed: %w", err)
	}

	s, err := t.factory.ThanosQuerierGrpcTLSSecret()
	if err != nil {
		return fmt.Errorf("error initializing Thanos Querier Client GRPC TLS secret: %w", err)
	}

	s, err = t.factory.HashSecret(s,
		"ca.crt", string(grpcTLS.Data["ca.crt"]),
		"client.crt", string(grpcTLS.Data["thanos-querier-client.crt"]),
		"client.key", string(grpcTLS.Data["thanos-querier-client.key"]),
	)
	if err != nil {
		return fmt.Errorf("error hashing Thanos Querier Client GRPC TLS secret: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("error creating Thanos Querier Client GRPC TLS secret: %w", err)
	}

	err = t.client.DeleteHashedSecret(
		ctx,
		s.GetNamespace(),
		"thanos-querier-grpc-tls",
		s.Labels["monitoring.openshift.io/hash"],
	)
	if err != nil {
		return fmt.Errorf("error creating Thanos Querier Client GRPC TLS secret: %w", err)
	}

	{
		dep, err := t.factory.ThanosQuerierDeployment(
			s,
			*t.config.ClusterMonitoringConfiguration.UserWorkloadEnabled,
		)
		if err != nil {
			return fmt.Errorf("initializing Thanos Querier Deployment failed: %w", err)
		}

		err = t.client.CreateOrUpdateDeployment(ctx, dep)
		if err != nil {
			return fmt.Errorf("reconciling Thanos Querier Deployment failed: %w", err)
		}
	}

	{
		pdb, err := t.factory.ThanosQuerierPodDisruptionBudget()
		if err != nil {
			return fmt.Errorf("initializing ThanosQuerier PodDisruptionBudget failed: %w", err)
		}

		if pdb != nil {
			err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb)
			if err != nil {
				return fmt.Errorf("reconciling ThanosQuerier PodDisruptionBudget failed: %w", err)
			}
		}
	}

	tqsm, err := t.factory.ThanosQuerierServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing Thanos Querier ServiceMonitor failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, tqsm)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Querier ServiceMonitor failed: %w", err)
	}

	tqpr, err := t.factory.ThanosQuerierPrometheusRule()
	if err != nil {
		return fmt.Errorf("initializing Thanos Querier PrometheusRule failed: %w", err)
	}

	err = t.client.CreateOrUpdatePrometheusRule(ctx, tqpr)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Querier PrometheusRule failed: %w", err)
	}

	return nil
}
