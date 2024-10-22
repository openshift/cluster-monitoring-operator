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
		return errors.Wrap(err, "initializing Thanos Querier Service failed")
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Querier Service failed")
	}

	hasRoutes, err := t.client.HasRouteCapability(ctx)
	if err != nil {
		return errors.Wrap(err, "checking for Route capability failed")
	}
	if hasRoutes {
		r, err := t.factory.ThanosQuerierRoute()
		if err != nil {
			return errors.Wrap(err, "initializing Thanos Querier Route failed")
		}

		err = t.client.CreateOrUpdateRoute(ctx, r)
		if err != nil {
			return errors.Wrap(err, "reconciling Thanos Querier Route failed")
		}

		_, err = t.client.WaitForRouteReady(ctx, r)
		if err != nil {
			return errors.Wrap(err, "waiting for Thanos Querier Route to become ready failed")
		}
	}

	s, err := t.factory.ThanosQuerierOauthCookieSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier OAuth Cookie Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ctx, s)
	if err != nil {
		return errors.Wrap(err, "creating Thanos Querier OAuth Cookie Secret failed")
	}

	rs, err := t.factory.ThanosQuerierRBACProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier RBAC proxy Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ctx, rs)
	if err != nil {
		return errors.Wrap(err, "creating Thanos Querier RBAC proxy Secret failed")
	}

	rs, err = t.factory.ThanosQuerierRBACProxyRulesSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier RBAC proxy rules Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ctx, rs)
	if err != nil {
		return errors.Wrap(err, "creating Thanos Querier RBAC proxy rules Secret failed")
	}

	rs, err = t.factory.ThanosQuerierRBACProxyMetricsSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier RBAC proxy metrics Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ctx, rs)
	if err != nil {
		return errors.Wrap(err, "creating Thanos Querier RBAC proxy metrics Secret failed")
	}

	sa, err := t.factory.ThanosQuerierServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier ServiceAccount failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Querier ServiceAccount failed")
	}

	cr, err := t.factory.ThanosQuerierClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Querier ClusterRole failed")
	}

	crb, err := t.factory.ThanosQuerierClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Querier ClusterRoleBinding failed")
	}

	grpcTLS, err := t.factory.GRPCSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier GRPC secret failed")
	}

	grpcTLS, err = t.client.WaitForSecret(ctx, grpcTLS)
	if err != nil {
		return errors.Wrap(err, "waiting for Thanos Querier GRPC secret failed")
	}

	s, err = t.factory.ThanosQuerierGrpcTLSSecret()
	if err != nil {
		return errors.Wrap(err, "error initializing Thanos Querier Client GRPC TLS secret")
	}

	s, err = t.factory.HashSecret(s,
		"ca.crt", string(grpcTLS.Data["ca.crt"]),
		"client.crt", string(grpcTLS.Data["thanos-querier-client.crt"]),
		"client.key", string(grpcTLS.Data["thanos-querier-client.key"]),
	)
	if err != nil {
		return errors.Wrap(err, "error hashing Thanos Querier Client GRPC TLS secret")
	}

	err = t.client.CreateOrUpdateSecret(ctx, s)
	if err != nil {
		return errors.Wrap(err, "error creating Thanos Querier Client GRPC TLS secret")
	}

	err = t.client.DeleteHashedSecret(
		ctx,
		s.GetNamespace(),
		"thanos-querier-grpc-tls",
		s.Labels["monitoring.openshift.io/hash"],
	)
	if err != nil {
		return errors.Wrap(err, "error creating Thanos Querier Client GRPC TLS secret")
	}

	{
		// Create trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.ThanosQuerierTrustedCABundle()
		if err != nil {
			return errors.Wrap(err, "initializing Thanos Querier trusted CA bundle ConfigMap failed")
		}

		cbs := &caBundleSyncer{
			client:  t.client,
			factory: t.factory,
			prefix:  "thanos-querier",
		}
		trustedCA, err = cbs.syncTrustedCABundle(ctx, trustedCA)
		if err != nil {
			return errors.Wrap(err, "syncing Thanos Querier trusted CA bundle ConfigMap failed")
		}

		dep, err := t.factory.ThanosQuerierDeployment(
			s,
			*t.config.ClusterMonitoringConfiguration.UserWorkloadEnabled,
			trustedCA,
		)
		if err != nil {
			return errors.Wrap(err, "initializing Thanos Querier Deployment failed")
		}

		err = t.client.CreateOrUpdateDeployment(ctx, dep)
		if err != nil {
			return errors.Wrap(err, "reconciling Thanos Querier Deployment failed")
		}
	}

	{
		pdb, err := t.factory.ThanosQuerierPodDisruptionBudget()
		if err != nil {
			return errors.Wrap(err, "initializing ThanosQuerier PodDisruptionBudget failed")
		}

		if pdb != nil {
			err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb)
			if err != nil {
				return errors.Wrap(err, "reconciling ThanosQuerier PodDisruptionBudget failed")
			}
		}
	}

	tqsm, err := t.factory.ThanosQuerierServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, tqsm)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Querier ServiceMonitor failed")
	}

	tqpr, err := t.factory.ThanosQuerierPrometheusRule()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier PrometheusRule failed")
	}

	err = t.client.CreateOrUpdatePrometheusRule(ctx, tqpr)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Querier PrometheusRule failed")
	}

	return nil
}
