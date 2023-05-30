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
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/pkg/errors"
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

	if !t.config.ClusterMonitoringConfiguration.TelemeterClientConfig.IsEnabled() || t.config.ClusterMonitoringConfiguration.TelemeterClientConfig.IsEnabled() && t.config.RemoteWrite {
		return t.destroy(ctx)
	}

	return nil
}

func (t *TelemeterClientTask) create(ctx context.Context) error {
	cacm, err := t.factory.TelemeterClientServingCertsCABundle()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter Client serving certs CA Bundle ConfigMap failed")
	}

	_, err = t.client.CreateIfNotExistConfigMap(ctx, cacm)
	if err != nil {
		return errors.Wrap(err, "creating Telemeter Client serving certs CA Bundle ConfigMap failed")
	}

	sa, err := t.factory.TelemeterClientServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Service failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client ServiceAccount failed")
	}

	cr, err := t.factory.TelemeterClientClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client ClusterRole failed")
	}

	crb, err := t.factory.TelemeterClientClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client ClusterRoleBinding failed")
	}

	crb, err = t.factory.TelemeterClientClusterRoleBindingView()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client cluster monitoring view ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client cluster monitoring view ClusterRoleBinding failed")
	}

	svc, err := t.factory.TelemeterClientService()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Service failed")
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client Service failed")
	}

	s, err := t.factory.TelemeterClientSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Secret failed")
	}

	oldS, err := t.client.GetSecret(ctx, s.Namespace, s.Name)
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "getting Telemeter Client Secret failed")
	}
	if oldS != nil && string(oldS.Data["token"]) == t.config.ClusterMonitoringConfiguration.TelemeterClientConfig.Token {
		s.Data = oldS.Data
	}

	err = t.client.CreateOrUpdateSecret(ctx, s)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client Secret failed")
	}

	krs, err := t.factory.TelemeterClientKubeRbacProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client kube rbac proxy secret failed")
	}

	err = t.client.CreateOrUpdateSecret(ctx, krs)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client kube rbac proxy secret failed")
	}

	{
		// Create trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.TelemeterTrustedCABundle()
		if err != nil {
			return errors.Wrap(err, "initializing Telemeter client trusted CA bundle ConfigMap failed")
		}

		cbs := &caBundleSyncer{
			client:  t.client,
			factory: t.factory,
			prefix:  "telemeter",
		}
		trustedCA, err = cbs.syncTrustedCABundle(ctx, trustedCA)
		if err != nil {
			return errors.Wrap(err, "syncing Telemeter client CA bundle ConfigMap failed")
		}

		dep, err := t.factory.TelemeterClientDeployment(trustedCA, s)
		if err != nil {
			return errors.Wrap(err, "initializing Telemeter client Deployment failed")
		}

		err = t.client.CreateOrUpdateDeployment(ctx, dep)
		if err != nil {
			return errors.Wrap(err, "reconciling Telemeter client Deployment failed")
		}
	}

	rule, err := t.factory.TelemeterClientPrometheusRule()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Prometheus Rule failed")
	}

	err = t.client.CreateOrUpdatePrometheusRule(ctx, rule)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client Prometheus Rule failed")
	}

	sm, err := t.factory.TelemeterClientServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, sm)
	return errors.Wrap(err, "reconciling Telemeter client ServiceMonitor failed")
}

func (t *TelemeterClientTask) destroy(ctx context.Context) error {
	dep, err := t.factory.TelemeterClientDeployment(nil, nil)
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Deployment failed")
	}

	err = t.client.DeleteDeployment(ctx, dep)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client Deployment failed")
	}

	s, err := t.factory.TelemeterClientSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Secret failed")
	}

	err = t.client.DeleteSecret(ctx, s)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client Secret failed")
	}

	krs, err := t.factory.TelemeterClientKubeRbacProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client kube rbac proxy secrent failed")
	}

	err = t.client.DeleteSecret(ctx, krs)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client kube rbac proxy secret failed")
	}

	svc, err := t.factory.TelemeterClientService()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Service failed")
	}

	err = t.client.DeleteService(ctx, svc)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client Service failed")
	}

	crb, err := t.factory.TelemeterClientClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client ClusterRoleBinding failed")
	}

	err = t.client.DeleteClusterRoleBinding(ctx, crb)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client ClusterRoleBinding failed")
	}

	cr, err := t.factory.TelemeterClientClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client ClusterRole failed")
	}

	err = t.client.DeleteClusterRole(ctx, cr)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client ClusterRole failed")
	}

	sa, err := t.factory.TelemeterClientServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Service failed")
	}

	err = t.client.DeleteServiceAccount(ctx, sa)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client ServiceAccount failed")
	}

	sm, err := t.factory.TelemeterClientServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client ServiceMonitor failed")
	}

	err = t.client.DeleteServiceMonitor(ctx, sm)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client ServiceMonitor failed")
	}

	cacm, err := t.factory.TelemeterClientServingCertsCABundle()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter Client serving certs CA Bundle ConfigMap failed")
	}

	err = t.client.DeleteConfigMap(ctx, cacm)
	return errors.Wrap(err, "creating Telemeter Client serving certs CA Bundle ConfigMap failed")
}
