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
	"fmt"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/pkg/promqlgen"

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

func (t *TelemeterClientTask) Run() error {
	if t.config.ClusterMonitoringConfiguration.TelemeterClientConfig.IsEnabled() && !t.config.RemoteWrite {
		return t.create()
	}

	if !t.config.ClusterMonitoringConfiguration.TelemeterClientConfig.IsEnabled() || t.config.ClusterMonitoringConfiguration.TelemeterClientConfig.IsEnabled() && t.config.RemoteWrite {
		return t.destroy()
	}

	return nil
}

func (t *TelemeterClientTask) create() error {
	cacm, err := t.factory.TelemeterClientServingCertsCABundle()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter Client serving certs CA Bundle ConfigMap failed")
	}

	_, err = t.client.CreateIfNotExistConfigMap(cacm)
	if err != nil {
		return errors.Wrap(err, "creating Telemeter Client serving certs CA Bundle ConfigMap failed")
	}

	sa, err := t.factory.TelemeterClientServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Service failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(sa)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client ServiceAccount failed")
	}

	cr, err := t.factory.TelemeterClientClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client ClusterRole failed")
	}

	crb, err := t.factory.TelemeterClientClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client ClusterRoleBinding failed")
	}

	crb, err = t.factory.TelemeterClientClusterRoleBindingView()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client cluster monitoring view ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client cluster monitoring view ClusterRoleBinding failed")
	}

	svc, err := t.factory.TelemeterClientService()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Service failed")
	}

	err = t.client.CreateOrUpdateService(svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client Service failed")
	}

	s, err := t.factory.TelemeterClientSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Secret failed")
	}

	err = t.client.CreateOrUpdateSecret(s)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client Secret failed")
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
		trustedCA, err = cbs.syncTrustedCABundle(trustedCA)
		if err != nil {
			return errors.Wrap(err, "syncing Telemeter client CA bundle ConfigMap failed")
		}

		dep, err := t.factory.TelemeterClientDeployment(trustedCA)
		if err != nil {
			return errors.Wrap(err, "initializing Telemeter client Deployment failed")
		}

		err = t.client.CreateOrUpdateDeployment(dep)
		if err != nil {
			return errors.Wrap(err, "reconciling Telemeter client Deployment failed")
		}
	}

	rec, err := generateTelemeterWhitelistRec(t.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.TelemetryMatches)
	if err != nil {
		return errors.Wrap(err, "generating Telemeter client Prometheus Rule failed")
	}

	rule, err := t.factory.NewTelemeterPrometheusRecRuleFromString(rec)
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Prometheus Rule failed")
	}

	err = t.client.CreateOrUpdatePrometheusRule(rule)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client Prometheus Rule failed")
	}

	sm, err := t.factory.TelemeterClientServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(sm)
	return errors.Wrap(err, "reconciling Telemeter client ServiceMonitor failed")
}

func (t *TelemeterClientTask) destroy() error {
	dep, err := t.factory.TelemeterClientDeployment(nil)
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Deployment failed")
	}

	err = t.client.DeleteDeployment(dep)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client Deployment failed")
	}

	s, err := t.factory.TelemeterClientSecret()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Secret failed")
	}

	err = t.client.DeleteSecret(s)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client Secret failed")
	}

	svc, err := t.factory.TelemeterClientService()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Service failed")
	}

	err = t.client.DeleteService(svc)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client Service failed")
	}

	crb, err := t.factory.TelemeterClientClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client ClusterRoleBinding failed")
	}

	err = t.client.DeleteClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client ClusterRoleBinding failed")
	}

	cr, err := t.factory.TelemeterClientClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client ClusterRole failed")
	}

	err = t.client.DeleteClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client ClusterRole failed")
	}

	sa, err := t.factory.TelemeterClientServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Service failed")
	}

	err = t.client.DeleteServiceAccount(sa)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client ServiceAccount failed")
	}

	sm, err := t.factory.TelemeterClientServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client ServiceMonitor failed")
	}

	err = t.client.DeleteServiceMonitor(sm)
	if err != nil {
		return errors.Wrap(err, "deleting Telemeter client ServiceMonitor failed")
	}

	cacm, err := t.factory.TelemeterClientServingCertsCABundle()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter Client serving certs CA Bundle ConfigMap failed")
	}

	err = t.client.DeleteConfigMap(cacm)
	return errors.Wrap(err, "creating Telemeter Client serving certs CA Bundle ConfigMap failed")
}

func generateTelemeterWhitelistRec(telemetryMatches []string) (string, error) {
	expr, err := promqlgen.GroupLabelSelectors(telemetryMatches)
	if err != nil {
		return "", nil
	}
	return fmt.Sprintf(`count(%s)`, expr), nil
}
