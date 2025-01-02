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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

type TelemeterClientTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewTelemeterClientTask(client *client.Client, factory *manifests.Factory, config *manifests.Config) *TelemeterClientTask {
	return &TelemeterClientTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *TelemeterClientTask) Run(ctx context.Context) error {
	if t.config.ClusterMonitoringConfiguration.TelemeterClientConfig.IsEnabled() && !t.config.RemoteWrite {
		return t.create(ctx)
	}

	var reason string
	switch {
	case !t.config.ClusterMonitoringConfiguration.TelemeterClientConfig.IsEnabled():
		reason = "telemetry is explicitly disabled"
	case t.config.ClusterMonitoringConfiguration.TelemeterClientConfig.IsEnabled() && t.config.RemoteWrite:
		reason = "remote-write is enabled instead"
	}

	if reason != "" {
		klog.V(3).Infof("Telemeter client is disabled (because %s), existing related resources are to be destroyed.", reason)
		return t.destroy(ctx)
	}

	return nil
}

func (t *TelemeterClientTask) create(ctx context.Context) error {
	cacm, err := t.factory.TelemeterClientServingCertsCABundle()
	if err != nil {
		return fmt.Errorf("initializing Telemeter Client serving certs CA Bundle ConfigMap failed: %w", err)
	}

	_, err = t.client.CreateIfNotExistConfigMap(ctx, cacm)
	if err != nil {
		return fmt.Errorf("creating Telemeter Client serving certs CA Bundle ConfigMap failed: %w", err)
	}

	sa, err := t.factory.TelemeterClientServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("reconciling Telemeter client ServiceAccount failed: %w", err)
	}

	cr, err := t.factory.TelemeterClientClusterRole()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client ClusterRole failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("reconciling Telemeter client ClusterRole failed: %w", err)
	}

	crb, err := t.factory.TelemeterClientClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client ClusterRoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("reconciling Telemeter client ClusterRoleBinding failed: %w", err)
	}

	crb, err = t.factory.TelemeterClientClusterRoleBindingView()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client cluster monitoring view ClusterRoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("reconciling Telemeter client cluster monitoring view ClusterRoleBinding failed: %w", err)
	}

	svc, err := t.factory.TelemeterClientService()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling Telemeter client Service failed: %w", err)
	}

	s, err := t.factory.TelemeterClientSecret()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client Secret failed: %w", err)
	}

	oldS, err := t.client.GetSecret(ctx, s.Namespace, s.Name)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("getting Telemeter Client Secret failed: %w", err)
	}
	if oldS != nil && string(oldS.Data["token"]) == t.config.ClusterMonitoringConfiguration.TelemeterClientConfig.Token {
		s.Data = oldS.Data
	}

	err = t.client.CreateOrUpdateSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("reconciling Telemeter client Secret failed: %w", err)
	}

	krs, err := t.factory.TelemeterClientKubeRbacProxySecret()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client kube rbac proxy secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, krs)
	if err != nil {
		return fmt.Errorf("reconciling Telemeter client kube rbac proxy secret failed: %w", err)
	}

	{
		// Create trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.TelemeterTrustedCABundle()
		if err != nil {
			return fmt.Errorf("initializing Telemeter client trusted CA bundle ConfigMap failed: %w", err)
		}

		cbs := &caBundleSyncer{
			client:  t.client,
			factory: t.factory,
			prefix:  "telemeter",
		}
		trustedCA, err = cbs.syncTrustedCABundle(ctx, trustedCA)
		if err != nil {
			return fmt.Errorf("syncing Telemeter client CA bundle ConfigMap failed: %w", err)
		}

		dep, err := t.factory.TelemeterClientDeployment(trustedCA, s)
		if err != nil {
			return fmt.Errorf("initializing Telemeter client Deployment failed: %w", err)
		}

		err = t.client.CreateOrUpdateDeployment(ctx, dep)
		if err != nil {
			return fmt.Errorf("reconciling Telemeter client Deployment failed: %w", err)
		}
	}

	rule, err := t.factory.TelemeterClientPrometheusRule()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client Prometheus Rule failed: %w", err)
	}

	err = t.client.CreateOrUpdatePrometheusRule(ctx, rule)
	if err != nil {
		return fmt.Errorf("reconciling Telemeter client Prometheus Rule failed: %w", err)
	}

	sm, err := t.factory.TelemeterClientServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client ServiceMonitor failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, sm)
	if err != nil {
		return fmt.Errorf("reconciling Telemeter client ServiceMonitor failed: %w", err)
	}
	return nil
}

func (t *TelemeterClientTask) destroy(ctx context.Context) error {
	dep, err := t.factory.TelemeterClientDeployment(nil, nil)
	if err != nil {
		return fmt.Errorf("initializing Telemeter client Deployment failed: %w", err)
	}

	err = t.client.DeleteDeployment(ctx, dep)
	if err != nil {
		return fmt.Errorf("deleting Telemeter client Deployment failed: %w", err)
	}

	s, err := t.factory.TelemeterClientSecret()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client Secret failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("deleting Telemeter client Secret failed: %w", err)
	}

	krs, err := t.factory.TelemeterClientKubeRbacProxySecret()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client kube rbac proxy secrent failed: %w", err)
	}

	err = t.client.DeleteSecret(ctx, krs)
	if err != nil {
		return fmt.Errorf("deleting Telemeter client kube rbac proxy secret failed: %w", err)
	}

	svc, err := t.factory.TelemeterClientService()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client Service failed: %w", err)
	}

	err = t.client.DeleteService(ctx, svc)
	if err != nil {
		return fmt.Errorf("deleting Telemeter client Service failed: %w", err)
	}

	crb, err := t.factory.TelemeterClientClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client ClusterRoleBinding failed: %w", err)
	}

	err = t.client.DeleteClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("deleting Telemeter client ClusterRoleBinding failed: %w", err)
	}

	cr, err := t.factory.TelemeterClientClusterRole()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client ClusterRole failed: %w", err)
	}

	err = t.client.DeleteClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("deleting Telemeter client ClusterRole failed: %w", err)
	}

	sa, err := t.factory.TelemeterClientServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client Service failed: %w", err)
	}

	err = t.client.DeleteServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("deleting Telemeter client ServiceAccount failed: %w", err)
	}

	sm, err := t.factory.TelemeterClientServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing Telemeter client ServiceMonitor failed: %w", err)
	}

	err = t.client.DeleteServiceMonitor(ctx, sm)
	if err != nil {
		return fmt.Errorf("deleting Telemeter client ServiceMonitor failed: %w", err)
	}

	cacm, err := t.factory.TelemeterClientServingCertsCABundle()
	if err != nil {
		return fmt.Errorf("initializing Telemeter Client serving certs CA Bundle ConfigMap failed: %w", err)
	}

	err = t.client.DeleteConfigMap(ctx, cacm)
	if err != nil {
		return fmt.Errorf("deleting Telemeter Client serving certs CA Bundle ConfigMap failed: %w", err)
	}
	return nil
}
