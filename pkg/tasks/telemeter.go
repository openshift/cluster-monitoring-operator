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
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
)

type TelemeterClientTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.TelemeterClientConfig
}

func NewTelemeterClientTask(client *client.Client, factory *manifests.Factory, config *manifests.TelemeterClientConfig) *TelemeterClientTask {
	return &TelemeterClientTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *TelemeterClientTask) Run() error {
	return t.destroy()
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
