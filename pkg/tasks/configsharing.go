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
	"errors"
	"fmt"
	"net/url"

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
		return fmt.Errorf("checking for Route capability failed: %w", err)
	}
	if hasRoutes {
		promRoute, err := t.factory.PrometheusK8sAPIRoute()
		if err != nil {
			return fmt.Errorf("initializing Prometheus Route failed: %w", err)
		}

		promURL, err = t.client.GetRouteURL(ctx, promRoute)
		if err != nil {
			return fmt.Errorf("failed to retrieve Prometheus host: %w", err)
		}

		optionalMonitoringEnabled, err := t.client.HasOptionalMonitoringCapability(ctx)
		if err != nil {
			return fmt.Errorf("checking for optional monitoring capability failed: %w", err)
		}
		if t.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.IsEnabled() && optionalMonitoringEnabled {
			amRoute, err := t.factory.AlertmanagerRoute()
			if err != nil {
				return fmt.Errorf("initializing Alertmanager Route failed: %w", err)
			}

			amURL, err = t.client.GetRouteURL(ctx, amRoute)
			if err != nil {
				return fmt.Errorf("failed to retrieve Alertmanager host: %w", err)
			}
		}

		thanosRoute, err := t.factory.ThanosQuerierRoute()
		if err != nil {
			return fmt.Errorf("initializing Thanos Querier Route failed: %w", err)
		}

		thanosURL, err = t.client.GetRouteURL(ctx, thanosRoute)
		if err != nil {
			return fmt.Errorf("failed to retrieve Thanos Querier host: %w", err)
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
			return fmt.Errorf("initializing Alertmanager User Workload Service failed: %w", err)
		}
	} else {
		// User-defined alerts are routed to the platform Alertmanager.
		svc, err = t.factory.AlertmanagerService()
		if err != nil {
			return fmt.Errorf("initializing Alertmanager Service failed: %w", err)
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
		return fmt.Errorf("reconciling %s/%s Config ConfigMap failed: %w", cm.Namespace, cm.Name, err)
	}

	return nil
}
