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

	apiutilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
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
		return fmt.Errorf("initializing serving certs CA Bundle ConfigMap failed: %w", err)
	}

	_, err = t.client.CreateIfNotExistConfigMap(ctx, cacm)
	if err != nil {
		return fmt.Errorf("creating serving certs CA Bundle ConfigMap failed: %w", err)
	}

	kscm, err := t.client.GetConfigmap(ctx, "openshift-config-managed", "kubelet-serving-ca")
	if err != nil {
		return fmt.Errorf("openshift-config-managed/kubelet-serving-ca: %w", err)
	}

	cacm, err = t.factory.PrometheusK8sKubeletServingCABundle(kscm.Data)
	if err != nil {
		return fmt.Errorf("initializing kubelet serving CA Bundle ConfigMap failed: %w", err)
	}

	err = t.client.CreateOrUpdateConfigMap(ctx, cacm)
	if err != nil {
		return fmt.Errorf("creating kubelet serving CA Bundle ConfigMap failed: %w", err)
	}

	hasRoutes, err := t.client.HasRouteCapability(ctx)
	if err != nil {
		return fmt.Errorf("checking for Route capability failed: %w", err)
	}
	if hasRoutes {
		r, err := t.factory.PrometheusK8sAPIRoute()
		if err != nil {
			return fmt.Errorf("initializing Prometheus API Route failed: %w", err)
		}

		err = t.client.CreateOrUpdateRoute(ctx, r)
		if err != nil {
			return fmt.Errorf("reconciling Prometheus API Route failed: %w", err)
		}

		_, err = t.client.WaitForRouteReady(ctx, r)
		if err != nil {
			return fmt.Errorf("waiting for Prometheus API Route to become ready failed: %w", err)
		}

		fr, err := t.factory.PrometheusK8sFederateRoute()
		if err != nil {
			return fmt.Errorf("initializing Prometheus Federate Route failed: %w", err)
		}

		err = t.client.CreateOrUpdateRoute(ctx, fr)
		if err != nil {
			return fmt.Errorf("reconciling Prometheus Federate Route failed: %w", err)
		}

		_, err = t.client.WaitForRouteReady(ctx, fr)
		if err != nil {
			return fmt.Errorf("waiting for Prometheus Federate Route to become ready failed: %w", err)
		}
	}

	rs, err := t.factory.PrometheusRBACProxySecret()
	if err != nil {
		return fmt.Errorf("initializing Prometheus RBAC proxy Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, rs)
	if err != nil {
		return fmt.Errorf("creating or updating Prometheus RBAC proxy Secret failed: %w", err)
	}

	rs, err = t.factory.PrometheusK8sRBACProxyWebSecret()
	if err != nil {
		return fmt.Errorf("initializing Prometheus RBAC proxy web Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, rs)
	if err != nil {
		return fmt.Errorf("creating or updating Prometheus RBAC proxy web Secret failed: %w", err)
	}

	sa, err := t.factory.PrometheusK8sServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing Prometheus ServiceAccount failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus ServiceAccount failed: %w", err)
	}

	cr, err := t.factory.PrometheusK8sClusterRole()
	if err != nil {
		return fmt.Errorf("initializing Prometheus ClusterRole failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus ClusterRole failed: %w", err)
	}

	crb, err := t.factory.PrometheusK8sClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Prometheus ClusterRoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus ClusterRoleBinding failed: %w", err)
	}

	amrb, err := t.factory.PrometheusK8sAlertmanagerRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Alertmanager RoleBinding failed: %w", err)
	}

	if t.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.IsEnabled() {
		if err = t.client.CreateOrUpdateRoleBinding(ctx, amrb); err != nil {
			return fmt.Errorf("reconciling Prometheus Alertmanager RoleBinding failed: %w", err)
		}
	} else {
		if err = t.client.DeleteRoleBinding(ctx, amrb); err != nil {
			return fmt.Errorf("deleting Prometheus Alertmanager RoleBinding failed: %w", err)
		}
	}

	rc, err := t.factory.PrometheusK8sRoleConfig()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Role config failed: %w", err)
	}

	err = t.client.CreateOrUpdateRole(ctx, rc)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus Role config failed: %w", err)
	}

	rl, err := t.factory.PrometheusK8sRoleList()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Role failed: %w", err)
	}

	for _, r := range rl.Items {
		err = t.client.CreateOrUpdateRole(ctx, &r)
		if err != nil {
			return fmt.Errorf("reconciling Prometheus Role %q failed: %w", r.Name, err)
		}
	}

	rbl, err := t.factory.PrometheusK8sRoleBindingList()
	if err != nil {
		return fmt.Errorf("initializing Prometheus RoleBinding failed: %w", err)
	}

	for _, rb := range rbl.Items {
		err = t.client.CreateOrUpdateRoleBinding(ctx, &rb)
		if err != nil {
			return fmt.Errorf("reconciling Prometheus RoleBinding %q failed: %w", rb.Name, err)
		}
	}

	rbc, err := t.factory.PrometheusK8sRoleBindingConfig()
	if err != nil {
		return fmt.Errorf("initializing Prometheus config RoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateRoleBinding(ctx, rbc)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus config RoleBinding failed: %w", err)
	}

	pm, err := t.factory.PrometheusK8sPrometheusRule()
	if err != nil {
		return fmt.Errorf("initializing Prometheus rules PrometheusRule failed: %w", err)
	}

	err = t.client.CreateOrUpdatePrometheusRule(ctx, pm)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus rules PrometheusRule failed: %w", err)
	}

	tsRule, err := t.factory.PrometheusK8sThanosSidecarPrometheusRule()
	if err != nil {
		return fmt.Errorf("initializing Thanos Sidecar rules failed: %w", err)
	}

	err = t.client.CreateOrUpdatePrometheusRule(ctx, tsRule)
	if err != nil {
		return fmt.Errorf("reconciling Thanos Sidecar rules PrometheusRule failed: %w", err)
	}

	svc, err := t.factory.PrometheusK8sService()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus Service failed: %w", err)
	}

	svc, err = t.factory.PrometheusK8sServiceThanosSidecar()
	if err != nil {
		return fmt.Errorf("initializing Thanos sidecar Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling Thanos sidecar Service failed: %w", err)
	}

	// There is no need to hash metrics client certs as Prometheus does that in-process.
	metricsCerts, err := t.factory.MetricsClientCerts()
	if err != nil {
		return fmt.Errorf("initializing Metrics Client Certs secret failed: %w", err)
	}

	_, err = t.client.WaitForSecret(ctx, metricsCerts)
	if err != nil {
		return fmt.Errorf("waiting for Metrics Client Certs secret failed: %w", err)
	}

	federateCerts, err := t.factory.FederateClientCerts()
	if err != nil {
		return fmt.Errorf("initializing Federate Client Certs secret failed: %w", err)
	}

	_, err = t.client.WaitForSecret(ctx, federateCerts)
	if err != nil {
		return fmt.Errorf("waiting for Federate Client Certs secret failed: %w", err)
	}

	grpcTLS, err := t.factory.GRPCSecret()
	if err != nil {
		return fmt.Errorf("initializing Prometheus GRPC secret failed: %w", err)
	}

	grpcTLS, err = t.client.WaitForSecret(ctx, grpcTLS)
	if err != nil {
		return fmt.Errorf("waiting for Prometheus GRPC secret failed: %w", err)
	}

	s, err := t.factory.PrometheusK8sGrpcTLSSecret()
	if err != nil {
		return fmt.Errorf("error initializing Prometheus Client GRPC TLS secret: %w", err)
	}

	s, err = t.factory.HashSecret(s,
		"ca.crt", string(grpcTLS.Data["ca.crt"]),
		"server.crt", string(grpcTLS.Data["prometheus-server.crt"]),
		"server.key", string(grpcTLS.Data["prometheus-server.key"]),
	)
	if err != nil {
		return fmt.Errorf("error hashing Prometheus Client GRPC TLS secret: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("error creating Prometheus Client GRPC TLS secret: %w", err)
	}

	err = t.client.DeleteHashedSecret(
		ctx,
		s.GetNamespace(),
		"prometheus-k8s-grpc-tls",
		s.Labels["monitoring.openshift.io/hash"],
	)
	if err != nil {
		return fmt.Errorf("error creating Prometheus Client GRPC TLS secret: %w", err)
	}

	{
		pdb, err := t.factory.PrometheusK8sPodDisruptionBudget()
		if err != nil {
			return fmt.Errorf("initializing Prometheus PodDisruptionBudget object failed: %w", err)
		}

		if pdb != nil {
			err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb)
			if err != nil {
				return fmt.Errorf("reconciling Prometheus PodDisruptionBudget object failed: %w", err)
			}
		}
	}

	telemetrySecret, err := t.factory.PrometheusK8sTelemetrySecret()
	if err != nil {
		return fmt.Errorf("initializing Prometheus telemetry secret failed: %w", err)
	}

	if t.config.ClusterMonitoringConfiguration.TelemeterClientConfig.IsEnabled() && t.config.RemoteWrite {
		klog.V(4).Info("updating Prometheus telemetry secret")
		if err = t.client.CreateOrUpdateSecret(ctx, telemetrySecret); err != nil {
			return fmt.Errorf("reconciling Prometheus telemetry secret failed: %w", err)
		}
	} else {
		klog.V(4).Info("deleting Prometheus telemetry secret")
		if err = t.client.DeleteSecret(ctx, telemetrySecret); err != nil {
			return fmt.Errorf("deleting Prometheus telemetry secret failed: %w", err)
		}
	}

	{
		// Create trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.PrometheusK8sTrustedCABundle()
		if err != nil {
			return fmt.Errorf("initializing Prometheus CA bundle ConfigMap failed: %w", err)
		}

		err = t.client.CreateOrUpdateConfigMap(ctx, trustedCA)
		if err != nil {
			return fmt.Errorf("reconciling Prometheus trusted CA bundle ConfigMap failed: %w", err)
		}

		secret, err := t.factory.PrometheusK8sAdditionalAlertManagerConfigsSecret()
		if err != nil {
			return fmt.Errorf("initializing Prometheus additionalAlertmanagerConfigs secret failed: %w", err)
		}

		klog.V(4).Info("reconciling Prometheus additionalAlertmanagerConfigs secret")
		if err = t.client.CreateOrUpdateSecret(ctx, secret); err != nil {
			return fmt.Errorf("reconciling Prometheus additionalAlertmanagerConfigs secret failed: %w", err)
		}

		klog.V(4).Info("initializing Prometheus object")
		p, err := t.factory.PrometheusK8s(s, telemetrySecret)
		if err != nil {
			return fmt.Errorf("initializing Prometheus object failed: %w", err)
		}

		klog.V(4).Info("reconciling Prometheus object")
		_, err = t.client.CreateOrUpdatePrometheus(ctx, p)
		if err != nil {
			return fmt.Errorf("reconciling Prometheus object failed: %w", err)
		}
	}

	smp, err := t.factory.PrometheusK8sPrometheusServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Prometheus ServiceMonitor failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smp)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus Prometheus ServiceMonitor failed: %w", err)
	}

	smt, err := t.factory.PrometheusK8sThanosSidecarServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Thanos sidecar ServiceMonitor failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smt)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus Thanos sidecar ServiceMonitor failed: %w", err)
	}

	return nil
}
