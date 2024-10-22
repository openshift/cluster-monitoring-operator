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

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
	apiutilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"
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

func (t *PrometheusTask) Run(ctx context.Context) error {
	errs := []error{}

	err := t.create(ctx)
	if err != nil {
		klog.V(4).ErrorS(err, "updation of prometheus failed")
		errs = append(errs, err)
	}

	// NOTE: the validation task is run even if creation fails so that
	// existing deployment is validated.
	validation := NewPrometheusValidationTask(t.client, t.factory)
	errs = append(errs, validation.Run(ctx))

	return apiutilerrors.NewAggregate(errs)
}

func (t *PrometheusTask) create(ctx context.Context) error {
	cacm, err := t.factory.PrometheusK8sServingCertsCABundle()
	if err != nil {
		return errors.Wrap(err, "initializing serving certs CA Bundle ConfigMap failed")
	}

	_, err = t.client.CreateIfNotExistConfigMap(ctx, cacm)
	if err != nil {
		return errors.Wrap(err, "creating serving certs CA Bundle ConfigMap failed")
	}

	kscm, err := t.client.GetConfigmap(ctx, "openshift-config-managed", "kubelet-serving-ca")
	if err != nil {
		return errors.Wrap(err, "openshift-config-managed/kubelet-serving-ca")
	}

	cacm, err = t.factory.PrometheusK8sKubeletServingCABundle(kscm.Data)
	if err != nil {
		return errors.Wrap(err, "initializing kubelet serving CA Bundle ConfigMap failed")
	}

	err = t.client.CreateOrUpdateConfigMap(ctx, cacm)
	if err != nil {
		return errors.Wrap(err, "creating kubelet serving CA Bundle ConfigMap failed")
	}

	hasRoutes, err := t.client.HasRouteCapability(ctx)
	if err != nil {
		return errors.Wrap(err, "checking for Route capability failed")
	}
	if hasRoutes {
		r, err := t.factory.PrometheusK8sAPIRoute()
		if err != nil {
			return errors.Wrap(err, "initializing Prometheus API Route failed")
		}

		err = t.client.CreateOrUpdateRoute(ctx, r)
		if err != nil {
			return errors.Wrap(err, "reconciling Prometheus API Route failed")
		}

		_, err = t.client.WaitForRouteReady(ctx, r)
		if err != nil {
			return errors.Wrap(err, "waiting for Prometheus API Route to become ready failed")
		}

		fr, err := t.factory.PrometheusK8sFederateRoute()
		if err != nil {
			return errors.Wrap(err, "initializing Prometheus Federate Route failed")
		}

		err = t.client.CreateOrUpdateRoute(ctx, fr)
		if err != nil {
			return errors.Wrap(err, "reconciling Prometheus Federate Route failed")
		}

		_, err = t.client.WaitForRouteReady(ctx, fr)
		if err != nil {
			return errors.Wrap(err, "waiting for Prometheus Federate Route to become ready failed")
		}
	}

	ps, err := t.factory.PrometheusK8sProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus proxy Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ctx, ps)
	if err != nil {
		return errors.Wrap(err, "creating Prometheus proxy Secret failed")
	}

	rs, err := t.factory.PrometheusRBACProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus RBAC proxy Secret failed")
	}

	err = t.client.CreateOrUpdateSecret(ctx, rs)
	if err != nil {
		return errors.Wrap(err, "creating or updating Prometheus RBAC proxy Secret failed")
	}

	sa, err := t.factory.PrometheusK8sServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus ServiceAccount failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus ServiceAccount failed")
	}

	cr, err := t.factory.PrometheusK8sClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus ClusterRole failed")
	}

	crb, err := t.factory.PrometheusK8sClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus ClusterRoleBinding failed")
	}

	amrb, err := t.factory.PrometheusK8sAlertmanagerRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Alertmanager RoleBinding failed")
	}

	if t.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.IsEnabled() {
		if err = t.client.CreateOrUpdateRoleBinding(ctx, amrb); err != nil {
			return errors.Wrap(err, "reconciling Prometheus Alertmanager RoleBinding failed")
		}
	} else {
		if err = t.client.DeleteRoleBinding(ctx, amrb); err != nil {
			return errors.Wrap(err, "deleting Prometheus Alertmanager RoleBinding failed")
		}
	}

	rc, err := t.factory.PrometheusK8sRoleConfig()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Role config failed")
	}

	err = t.client.CreateOrUpdateRole(ctx, rc)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Role config failed")
	}

	rl, err := t.factory.PrometheusK8sRoleList()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Role failed")
	}

	for _, r := range rl.Items {
		err = t.client.CreateOrUpdateRole(ctx, &r)
		if err != nil {
			return errors.Wrapf(err, "reconciling Prometheus Role %q failed", r.Name)
		}
	}

	rbl, err := t.factory.PrometheusK8sRoleBindingList()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus RoleBinding failed")
	}

	for _, rb := range rbl.Items {
		err = t.client.CreateOrUpdateRoleBinding(ctx, &rb)
		if err != nil {
			return errors.Wrapf(err, "reconciling Prometheus RoleBinding %q failed", rb.Name)
		}
	}

	rbc, err := t.factory.PrometheusK8sRoleBindingConfig()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus config RoleBinding failed")
	}

	err = t.client.CreateOrUpdateRoleBinding(ctx, rbc)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus config RoleBinding failed")
	}

	pm, err := t.factory.PrometheusK8sPrometheusRule()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus rules PrometheusRule failed")
	}

	err = t.client.CreateOrUpdatePrometheusRule(ctx, pm)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus rules PrometheusRule failed")
	}

	tsRule, err := t.factory.PrometheusK8sThanosSidecarPrometheusRule()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Sidecar rules failed")
	}

	err = t.client.CreateOrUpdatePrometheusRule(ctx, tsRule)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Sidecar rules PrometheusRule failed")
	}

	svc, err := t.factory.PrometheusK8sService()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Service failed")
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Service failed")
	}

	svc, err = t.factory.PrometheusK8sServiceThanosSidecar()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos sidecar Service failed")
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos sidecar Service failed")
	}

	// There is no need to hash metrics client certs as Prometheus does that in-process.
	metricsCerts, err := t.factory.MetricsClientCerts()
	if err != nil {
		return errors.Wrap(err, "initializing Metrics Client Certs secret failed")
	}

	_, err = t.client.WaitForSecret(ctx, metricsCerts)
	if err != nil {
		return errors.Wrap(err, "waiting for Metrics Client Certs secret failed")
	}

	federateCerts, err := t.factory.FederateClientCerts()
	if err != nil {
		return errors.Wrap(err, "initializing Federate Client Certs secret failed")
	}

	_, err = t.client.WaitForSecret(ctx, federateCerts)
	if err != nil {
		return errors.Wrap(err, "waiting for Federate Client Certs secret failed")
	}

	grpcTLS, err := t.factory.GRPCSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus GRPC secret failed")
	}

	grpcTLS, err = t.client.WaitForSecret(ctx, grpcTLS)
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

	err = t.client.CreateOrUpdateSecret(ctx, s)
	if err != nil {
		return errors.Wrap(err, "error creating Prometheus Client GRPC TLS secret")
	}

	err = t.client.DeleteHashedSecret(
		ctx,
		s.GetNamespace(),
		"prometheus-k8s-grpc-tls",
		s.Labels["monitoring.openshift.io/hash"],
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
			err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb)
			if err != nil {
				return errors.Wrap(err, "reconciling Prometheus PodDisruptionBudget object failed")
			}
		}
	}

	telemetrySecret, err := t.factory.PrometheusK8sTelemetrySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus telemetry secret failed")
	}

	if t.config.ClusterMonitoringConfiguration.TelemeterClientConfig.IsEnabled() && t.config.RemoteWrite {
		klog.V(4).Info("updating Prometheus telemetry secret")
		if err = t.client.CreateOrUpdateSecret(ctx, telemetrySecret); err != nil {
			return errors.Wrap(err, "reconciling Prometheus telemetry secret failed")
		}
	} else {
		klog.V(4).Info("deleting Prometheus telemetry secret")
		if err = t.client.DeleteSecret(ctx, telemetrySecret); err != nil {
			return errors.Wrap(err, "deleting Prometheus telemetry secret failed")
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
		trustedCA, err = cbs.syncTrustedCABundle(ctx, trustedCA)
		if err != nil {
			return errors.Wrap(err, "syncing Prometheus trusted CA bundle ConfigMap failed")
		}

		secret, err := t.factory.PrometheusK8sAdditionalAlertManagerConfigsSecret()
		if err != nil {
			return errors.Wrap(err, "initializing Prometheus additionalAlertmanagerConfigs secret failed")
		}

		klog.V(4).Info("reconciling Prometheus additionalAlertmanagerConfigs secret")
		if err = t.client.CreateOrUpdateSecret(ctx, secret); err != nil {
			return errors.Wrap(err, "reconciling Prometheus additionalAlertmanagerConfigs secret failed")
		}

		klog.V(4).Info("initializing Prometheus object")
		p, err := t.factory.PrometheusK8s(s, trustedCA, telemetrySecret)
		if err != nil {
			return errors.Wrap(err, "initializing Prometheus object failed")
		}

		klog.V(4).Info("reconciling Prometheus object")
		err = t.client.CreateOrUpdatePrometheus(ctx, p)
		if err != nil {
			return errors.Wrap(err, "reconciling Prometheus object failed")
		}
	}

	smp, err := t.factory.PrometheusK8sPrometheusServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Prometheus ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smp)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Prometheus ServiceMonitor failed")
	}

	smt, err := t.factory.PrometheusK8sThanosSidecarServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Prometheus Thanos sidecar ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smt)
	if err != nil {
		return errors.Wrap(err, "reconciling Prometheus Thanos sidecar ServiceMonitor failed")
	}

	return nil
}
