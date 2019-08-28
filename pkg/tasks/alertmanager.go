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

type AlertmanagerTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewAlertmanagerTask(client *client.Client, factory *manifests.Factory) *AlertmanagerTask {
	return &AlertmanagerTask{
		client:  client,
		factory: factory,
	}
}

func (t *AlertmanagerTask) Run() error {
	r, err := t.factory.AlertmanagerRoute()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager Route failed")
	}

	err = t.client.CreateRouteIfNotExists(r)
	if err != nil {
		return errors.Wrap(err, "creating Alertmanager Route failed")
	}

	host, err := t.client.WaitForRouteReady(r)
	if err != nil {
		return errors.Wrap(err, "waiting for Alertmanager Route to become ready failed")
	}

	s, err := t.factory.AlertmanagerConfig()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager configuration Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(s)
	if err != nil {
		return errors.Wrap(err, "creating Alertmanager configuration Secret failed")
	}

	cr, err := t.factory.AlertmanagerClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "reconciling Alertmanager ClusterRole failed")
	}

	crb, err := t.factory.AlertmanagerClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "reconciling Alertmanager ClusterRoleBinding failed")
	}

	sa, err := t.factory.AlertmanagerServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager ServiceAccount failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(sa)
	if err != nil {
		return errors.Wrap(err, "reconciling Alertmanager ServiceAccount failed")
	}

	ps, err := t.factory.AlertmanagerProxySecret()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager proxy Secret failed")
	}

	err = t.client.CreateIfNotExistSecret(ps)
	if err != nil {
		return errors.Wrap(err, "creating Alertmanager proxy Secret failed")
	}

	svc, err := t.factory.AlertmanagerService()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager Service failed")
	}

	err = t.client.CreateOrUpdateService(svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Alertmanager Service failed")
	}
	{
		// Create trusted CA bundle ConfigMap.
		trustedCA, err := t.factory.AlertmanagerTrustedCABundle()
		if err != nil {
			return errors.Wrap(err, "initializing Alertmanager CA bundle ConfigMap failed")
		}

		trustedCA, err = t.client.CreateIfNotExistConfigMap(trustedCA)
		if err != nil {
			return errors.Wrap(err, " creating Alertmanager CA bundle ConfigMap failed")
		}

		// In the case when there is no data but the ConfigMap is there, we just continue.
		// We will catch this on the next loop.
		trustedCA = t.factory.HashTrustedCA(trustedCA, "alertmanager")
		if trustedCA != nil {
			err = t.client.CreateOrUpdateConfigMap(trustedCA)
			if err != nil {
				return errors.Wrap(err, "reconciling Alertmanager CA bundle ConfigMap failed")
			}

			err = t.client.DeleteHashedConfigMap(
				string(trustedCA.Labels["monitoring.openshift.io/hash"]),
				"alertmanager",
			)
			if err != nil {
				return errors.Wrap(err, "deleting old Alertmanager configmaps failed")
			}
		}

		a, err := t.factory.AlertmanagerMain(host, trustedCA)
		if err != nil {
			return errors.Wrap(err, "initializing Alertmanager object failed")
		}

		err = t.client.CreateOrUpdateAlertmanager(a)
		if err != nil {
			return errors.Wrap(err, "reconciling Alertmanager object failed")
		}
		err = t.client.WaitForAlertmanager(a)
		if err != nil {
			return errors.Wrap(err, "waiting for Alertmanager object changes failed")
		}
	}
	smam, err := t.factory.AlertmanagerServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Alertmanager ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smam)
	return errors.Wrap(err, "reconciling Alertmanager ServiceMonitor failed")
}
