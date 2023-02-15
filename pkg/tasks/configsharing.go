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
	"net/url"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

type ConfigSharingTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewConfigSharingTask(client *client.Client, factory *manifests.Factory, config *manifests.Config) *ConfigSharingTask {
	return &ConfigSharingTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *ConfigSharingTask) Run(ctx context.Context) error {
	var amURL, promURL, thanosURL *url.URL
	hasRoutes, err := t.client.HasRouteCapability(ctx)
	if err != nil {
		return errors.Wrap(err, "checking for Route capability failed")
	}
	if hasRoutes {
		promRoute, err := t.factory.PrometheusK8sAPIRoute()
		if err != nil {
			return errors.Wrap(err, "initializing Prometheus Route failed")
		}

		promURL, err = t.client.GetRouteURL(ctx, promRoute)
		if err != nil {
			return errors.Wrap(err, "failed to retrieve Prometheus host")
		}

		if t.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.IsEnabled() {
			amRoute, err := t.factory.AlertmanagerRoute()
			if err != nil {
				return errors.Wrap(err, "initializing Alertmanager Route failed")
			}

			amURL, err = t.client.GetRouteURL(ctx, amRoute)
			if err != nil {
				return errors.Wrap(err, "failed to retrieve Alertmanager host")
			}
		}

		thanosRoute, err := t.factory.ThanosQuerierRoute()
		if err != nil {
			return errors.Wrap(err, "initializing Thanos Querier Route failed")
		}

		thanosURL, err = t.client.GetRouteURL(ctx, thanosRoute)
		if err != nil {
			return errors.Wrap(err, "failed to retrieve Thanos Querier host")
		}
	}

	var (
		svc                  *v1.Service
		webPort, tenancyPort int
	)
	if t.config.UserWorkloadConfiguration.Alertmanager.Enabled {
		// User-defined alerts are routed to the UWM Alertmanager.
		svc, err = t.factory.AlertmanagerUserWorkloadService()
		if err != nil {
			return errors.Wrap(err, "initializing Alertmanager User Workload Service failed")
		}
	} else {
		// User-defined alerts are routed to the platform Alertmanager.
		svc, err = t.factory.AlertmanagerService()
		if err != nil {
			return errors.Wrap(err, "initializing Alertmanager Service failed")
		}
	}

	for _, port := range svc.Spec.Ports {
		switch port.Name {
		case "web":
			webPort = int(port.Port)
		case "tenancy":
			tenancyPort = int(port.Port)
		}
	}

	if webPort == 0 {
		return errors.New("failed to find Alertmanager web port")
	}

	if tenancyPort == 0 {
		return errors.New("failed to find Alertmanager tenancy port")
	}

	cm := t.factory.SharingConfig(
		promURL,
		amURL,
		thanosURL,
		fmt.Sprintf("%s.%s.svc:%d", svc.Name, svc.Namespace, webPort),
		fmt.Sprintf("%s.%s.svc:%d", svc.Name, svc.Namespace, tenancyPort),
	)

	err = t.client.CreateOrUpdateConfigMap(ctx, cm)
	if err != nil {
		return errors.Wrapf(err, "reconciling %s/%s Config ConfigMap failed", cm.Namespace, cm.Name)
	}

	return nil
}
