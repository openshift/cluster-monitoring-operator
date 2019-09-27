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
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
)

type ThanosQuerierTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewThanosQuerierTask(client *client.Client, factory *manifests.Factory) *ThanosQuerierTask {
	return &ThanosQuerierTask{
		client:  client,
		factory: factory,
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

	d, err := t.factory.ThanosQuerierDeployment()
	if err != nil {
		return errors.Wrap(err, "initializing Thanos Querier Deployment failed")
	}

	err = t.client.CreateOrUpdateDeployment(d)
	if err != nil {
		return errors.Wrap(err, "reconciling Thanos Querier  Deployment failed")
	}

	return nil
}
