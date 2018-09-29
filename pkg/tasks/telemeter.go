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
}

func NewTelemeterClientTask(client *client.Client, factory *manifests.Factory) *TelemeterClientTask {
	return &TelemeterClientTask{
		client:  client,
		factory: factory,
	}
}

func (t *TelemeterClientTask) Run() error {
	sm, err := t.factory.TelemeterClientServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(sm)
	if err != nil {
		return errors.Wrap(err, "reconciling Telemeter client ServiceMonitor failed")
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
		return errors.Wrap(err, "creating Telemeter client Secret failed")
	}

	dep, err := t.factory.TelemeterClientDeployment()
	if err != nil {
		return errors.Wrap(err, "initializing Telemeter client Deployment failed")
	}

	err = t.client.CreateOrUpdateDeployment(dep)
	return errors.Wrap(err, "reconciling Telemeter client Deployment failed")
}
