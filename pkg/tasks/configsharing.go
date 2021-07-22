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

type ConfigSharingTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewConfigSharingTask(client *client.Client, factory *manifests.Factory) *ConfigSharingTask {
	return &ConfigSharingTask{
		client:  client,
		factory: factory,
	}
}

func (t *ConfigSharingTask) Run() error {
	cm := t.factory.SharingConfig()
	// delete the config map if it exists, err will be nil if it does not exist
	err := t.client.DeleteConfigMap(t.factory.SharingConfig())
	if err != nil {
		return errors.Wrapf(err, "failed to delete sharing config map %s/%s ", cm.Namespace, cm.Name)
	}

	return nil
}
