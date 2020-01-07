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
	"encoding/json"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ThanosQuerierTask struct {
	client             *client.Client
	factory            *manifests.Factory
	userWorkloadConfig *manifests.UserWorkloadConfig
}

func NewThanosQuerierTask(client *client.Client, factory *manifests.Factory, cfg *manifests.UserWorkloadConfig) *ThanosQuerierTask {
	return &ThanosQuerierTask{
		client:             client,
		factory:            factory,
		userWorkloadConfig: cfg,
	}
}

func (t *ThanosQuerierTask) Run() error {
	svc, err := t.factory.ThanosQuerierService()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier Service failed")
	}

	err = t.client.CreateOrUpdateService(svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Querier Service failed")
	}

	r, err := t.factory.ThanosQuerierRoute()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier Route failed")
	}

	err = t.client.CreateRouteIfNotExists(r)
	if err != nil {
		return errors.Wrap(err, "creating Thanos Querier Route failed")
	}

	_, err = t.client.WaitForRouteReady(r)
	if err != nil {
		return errors.Wrap(err, "waiting for Thanos Querier Route to become ready failed")
	}

	s, err := t.factory.ThanosQuerierOauthCookieSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier OAuth Cookie Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(s)
	if err != nil {
		return errors.Wrap(err, "creating Thanos Querier OAuth Cookie Secret failed")
	}

	c := t.client.KubernetesInterface()
	cm, err := c.CoreV1().Secrets(t.client.Namespace()).Get("grafana-datasources", metav1.GetOptions{})
	if err != nil {
		return errors.Wrap(err, "failed to retrieve Grafana datasources config")
	}
	d := &manifests.GrafanaDatasources{}
	err = json.Unmarshal(cm.Data["prometheus.yaml"], d)

	hs, err := t.factory.ThanosQuerierHtpasswdSecret(d.Datasources[0].BasicAuthPassword)
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier htpasswd Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(hs)
	if err != nil {
		return errors.Wrap(err, "creating Thanos Querier htpasswd Secret failed")
	}

	rs, err := t.factory.ThanosQuerierRBACProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier RBAC proxy Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(rs)
	if err != nil {
		return errors.Wrap(err, "creating Thanos Querier RBAC proxy Secret failed")
	}

	sa, err := t.factory.ThanosQuerierServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier ServiceAccount failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(sa)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Querier ServiceAccount failed")
	}

	cr, err := t.factory.ThanosQuerierClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Querier ClusterRole failed")
	}

	crb, err := t.factory.ThanosQuerierClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Querier ClusterRoleBinding failed")
	}

	grpcTLS, err := t.factory.GRPCSecret(nil)
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier GRPC secret failed")
	}

	grpcTLS, err = t.client.WaitForSecret(grpcTLS)
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

	err = t.client.CreateOrUpdateSecret(s)
	if err != nil {
		return errors.Wrap(err, "error creating Thanos Querier Client GRPC TLS secret")
	}

	err = t.client.DeleteHashedSecret(
		string(s.Labels["monitoring.openshift.io/hash"]),
		"thanos-querier-grpc-tls",
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

		trustedCA, err = t.client.CreateIfNotExistConfigMap(trustedCA)
		if err != nil {
			return errors.Wrap(err, "creating Thanos Querier trusted CA bundle ConfigMap failed")
		}

		// In the case when there is no data but the ConfigMap is there, we just continue.
		// We will catch this on the next loop.
		trustedCA = t.factory.HashTrustedCA(trustedCA, "thanos-querier")
		if trustedCA != nil {
			err = t.client.CreateOrUpdateConfigMap(trustedCA)
			if err != nil {
				return errors.Wrap(err, "reconciling Thanos Querier hashed trusted CA bundle ConfigMap failed")
			}

			err = t.client.DeleteHashedConfigMap(
				string(trustedCA.Labels["monitoring.openshift.io/hash"]),
				"thanos-querier",
			)
			if err != nil {
				return errors.Wrap(err, "deleting old Thanos Querier client configmaps failed")
			}
		}

		dep, err := t.factory.ThanosQuerierDeployment(s, t.userWorkloadConfig.IsEnabled(), trustedCA)
		if err != nil {
			return errors.Wrap(err, "initializing Thanos Querier Deployment failed")
		}

		err = t.client.CreateOrUpdateDeployment(dep)
		if err != nil {
			return errors.Wrap(err, "reconciling Thanos Querier Deployment failed")
		}
	}

	return nil
}
