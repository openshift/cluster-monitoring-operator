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
)

type ThanosRulerUserWorkloadTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.UserWorkloadConfig
}

func NewThanosRulerUserWorkloadTask(client *client.Client, factory *manifests.Factory, config *manifests.UserWorkloadConfig) *ThanosRulerUserWorkloadTask {
	return &ThanosRulerUserWorkloadTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *ThanosRulerUserWorkloadTask) Run() error {
	if t.config.IsEnabled() {
		return t.create()
	}

	return t.destroy()
}

func (t *ThanosRulerUserWorkloadTask) create() error {
	svc, err := t.factory.ThanosRulerService()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler Service failed")
	}

	err = t.client.CreateOrUpdateService(svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Ruler Service failed")
	}

	r, err := t.factory.ThanosRulerRoute()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler Route failed")
	}

	err = t.client.CreateRouteIfNotExists(r)
	if err != nil {
		return errors.Wrap(err, "creating Thanos Ruler Route failed")
	}

	_, err = t.client.WaitForRouteReady(r)
	if err != nil {
		return errors.Wrap(err, "waiting for Thanos Ruler Route to become ready failed")
	}

	cr, err := t.factory.ThanosRulerClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Ruler ClusterRole failed")
	}

	crb, err := t.factory.ThanosRulerClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Ruler ClusterRoleBinding failed")
	}

	moncrb, err := t.factory.ThanosRulerMonitoringClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler monitoring ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(moncrb)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Ruler monitoring ClusterRoleBinding failed")
	}

	sa, err := t.factory.ThanosRulerServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler ServiceAccount failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(sa)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Ruler ServiceAccount failed")
	}

	s, err := t.factory.ThanosRulerOauthCookieSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler OAuth Cookie Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(s)
	if err != nil {
		return errors.Wrap(err, "creating Thanos Ruler OAuth Cookie Secret failed")
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

	hs, err := t.factory.ThanosRulerHtpasswdSecret(d.Datasources[0].BasicAuthPassword)
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler htpasswd Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(hs)
	if err != nil {
		return errors.Wrap(err, "creating Thanos Ruler htpasswd Secret failed")
	}

	// Thanos components use https://godoc.org/github.com/prometheus/common/config#NewClientFromConfig
	// under the hood and the returned http.Client detects whenever the certificates are rotated,
	// so there is no need for us to rotate the CA.
	qcs, err := t.factory.ThanosRulerQueryConfigSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler query config Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(qcs)
	if err != nil {
		return errors.Wrap(err, "creating Thanos Ruler query config Secret failed")
	}

	// Thanos components use https://godoc.org/github.com/prometheus/common/config#NewClientFromConfig
	// under the hood and the returned http.Client detects whenever the certificates are rotated,
	// so there is no need for us to rotate the CA.
	acs, err := t.factory.ThanosRulerAlertmanagerConfigSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler Alertmanager config Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(acs)
	if err != nil {
		return errors.Wrap(err, "creating Thanos Ruler alertmanager config Secret failed")
	}

	{
		// Create trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.ThanosRulerTrustedCABundle()
		if err != nil {
			return errors.Wrap(err, "initializing Thanos Ruler trusted CA bundle ConfigMap failed")
		}

		trustedCA, err = t.client.CreateIfNotExistConfigMap(trustedCA)
		if err != nil {
			return errors.Wrap(err, "creating Thanos Ruler trusted CA bundle ConfigMap failed")
		}

		// In the case when there is no data but the ConfigMap is there, we just continue.
		// We will catch this on the next loop.
		trustedCA = t.factory.HashTrustedCA(trustedCA, "thanos-ruler")
		if trustedCA != nil {
			err = t.client.CreateOrUpdateConfigMap(trustedCA)
			if err != nil {
				return errors.Wrap(err, "reconciling Thanos Ruler hashed trusted CA bundle ConfigMap failed")
			}

			err = t.client.DeleteHashedConfigMap(
				string(trustedCA.Labels["monitoring.openshift.io/hash"]),
				"thanos-ruler",
			)
			if err != nil {
				return errors.Wrap(err, "deleting old Thanos Ruler client configmaps failed")
			}
		}

		grpcTLS, err := t.factory.GRPCSecret(nil)
		if err != nil {
			return errors.Wrap(err, "initializing UserWorkload Thanos Ruler GRPC secret failed")
		}

		grpcTLS, err = t.client.WaitForSecret(grpcTLS)
		if err != nil {
			return errors.Wrap(err, "waiting for UserWorkload Thanos Ruler GRPC secret failed")
		}

		s, err := t.factory.ThanosRulerGrpcTLSSecret()
		if err != nil {
			return errors.Wrap(err, "error initializing UserWorkload Thanos Ruler GRPC TLS secret")
		}

		s, err = t.factory.HashSecret(s,
			"ca.crt", string(grpcTLS.Data["ca.crt"]),
			"server.crt", string(grpcTLS.Data["prometheus-server.crt"]),
			"server.key", string(grpcTLS.Data["prometheus-server.key"]),
		)
		if err != nil {
			return errors.Wrap(err, "error hashing UserWorkload Thanos Ruler GRPC TLS secret")
		}

		err = t.client.CreateOrUpdateSecret(s)
		if err != nil {
			return errors.Wrap(err, "error creating UserWorkload Thanos Ruler GRPC TLS secret")
		}

		err = t.client.DeleteHashedSecret(
			string(s.Labels["monitoring.openshift.io/hash"]),
			"thanos-ruler-user-workload-grpc-tls",
		)
		if err != nil {
			return errors.Wrap(err, "error deleting expired UserWorkload Thanos Ruler GRPC TLS secret")
		}

		querierRoute, err := t.factory.ThanosQuerierRoute()
		if err != nil {
			return errors.Wrap(err, "initializing Thanos Querier Route failed")
		}
		queryURL, err := t.client.GetRouteURL(querierRoute)

		tr, err := t.factory.ThanosRulerCustomResource(queryURL.String(), trustedCA, s)
		if err != nil {
			return errors.Wrap(err, "initializing ThanosRuler object failed")
		}

		err = t.client.CreateOrUpdateThanosRuler(tr)
		if err != nil {
			return errors.Wrap(err, "reconciling ThanosRuler object failed")
		}

		err = t.client.WaitForThanosRuler(tr)
		if err != nil {
			return errors.Wrap(err, "waiting for ThanosRuler object changes failed")
		}
	}

	trsm, err := t.factory.ThanosRulerServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(trsm)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Ruler ServiceMonitor failed")
	}

	pm, err := t.factory.ThanosRulerPrometheusRule()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler PrometheusRule failed")
	}

	err = t.client.CreateOrUpdatePrometheusRule(pm)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Ruler PrometheusRule failed")
	}
	return nil
}

func (t *ThanosRulerUserWorkloadTask) destroy() error {
	prmrl, err := t.factory.ThanosRulerPrometheusRule()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler PrometheusRule failed")
	}

	err = t.client.DeletePrometheusRule(prmrl)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Ruler PrometheusRule failed")
	}

	svc, err := t.factory.ThanosRulerService()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler Service failed")
	}

	err = t.client.DeleteService(svc)
	if err != nil {
		return errors.Wrap(err, "deleting Thanos Ruler Service failed")
	}

	cr, err := t.factory.ThanosRulerClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler ClusterRole failed")
	}

	err = t.client.DeleteClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Ruler ClusterRole failed")
	}

	crb, err := t.factory.ThanosRulerClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "deleting Thanos Ruler ClusterRoleBinding failed")
	}

	err = t.client.DeleteClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "deleting Thanos Ruler ClusterRoleBinding failed")
	}

	sa, err := t.factory.ThanosRulerServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler ServiceAccount failed")
	}

	err = t.client.DeleteServiceAccount(sa)
	if err != nil {
		return errors.Wrap(err, "deleting Thanos Ruler ServiceAccount failed")
	}

	s, err := t.factory.ThanosRulerOauthCookieSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler OAuth Cookie Secret failed")
	}

	err = t.client.DeleteSecret(s)
	if err != nil {
		return errors.Wrap(err, "deleting Thanos Ruler OAuth Cookie Secret failed")
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

	hs, err := t.factory.ThanosRulerHtpasswdSecret(d.Datasources[0].BasicAuthPassword)
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler htpasswd Secret failed")
	}

	{
		// Create trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.ThanosRulerTrustedCABundle()
		if err != nil {
			return errors.Wrap(err, "initializing Thanos Ruler trusted CA bundle ConfigMap failed")
		}

		err = t.client.DeleteConfigMap(trustedCA)
		if err != nil {
			return errors.Wrap(err, "deleting Thanos Ruler trusted CA bundle ConfigMap failed")
		}

		tr, err := t.factory.ThanosRulerCustomResource("", trustedCA, hs)
		if err != nil {
			return errors.Wrap(err, "initializing ThanosRuler object failed")
		}

		err = t.client.DeleteThanosRuler(tr)
		if err != nil {
			return errors.Wrap(err, "deleting ThanosRuler object failed")
		}
	}

	err = t.client.DeleteSecret(hs)
	if err != nil {
		return errors.Wrap(err, "deleting Thanos Ruler htpasswd Secret failed")
	}

	qcs, err := t.factory.ThanosRulerQueryConfigSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler query config Secret failed")
	}

	err = t.client.DeleteSecret(qcs)
	if err != nil {
		return errors.Wrap(err, "deleting Thanos Ruler query config Secret failed")
	}

	grpcTLS, err := t.factory.GRPCSecret(nil)
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkload Thanos Ruler GRPC secret failed")
	}

	grpcTLS, err = t.client.WaitForSecret(grpcTLS)
	if err != nil {
		return errors.Wrap(err, "waiting for UserWorkload Thanos Ruler GRPC secret failed")
	}

	s, err = t.factory.ThanosRulerGrpcTLSSecret()
	if err != nil {
		return errors.Wrap(err, "error initializing UserWorkload Thanos Ruler GRPC TLS secret")
	}

	s, err = t.factory.HashSecret(s,
		"ca.crt", string(grpcTLS.Data["ca.crt"]),
		"server.crt", string(grpcTLS.Data["prometheus-server.crt"]),
		"server.key", string(grpcTLS.Data["prometheus-server.key"]),
	)
	if err != nil {
		return errors.Wrap(err, "error hashing UserWorkload Thanos Ruler GRPC TLS secret")
	}

	err = t.client.DeleteSecret(s)
	if err != nil {
		return errors.Wrap(err, "error deleting UserWorkload Thanos Ruler GRPC TLS secret")
	}

	acs, err := t.factory.ThanosRulerAlertmanagerConfigSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler Alertmanager config Secret failed")
	}

	err = t.client.DeleteSecret(acs)
	if err != nil {
		return errors.Wrap(err, "creating Thanos Ruler alertmanager config Secret failed")
	}

	trsm, err := t.factory.ThanosRulerServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Ruler ServiceMonitor failed")
	}

	err = t.client.DeleteServiceMonitor(trsm)
	return errors.Wrap(err, "deleting Thanos Ruler ServiceMonitor failed")
}
