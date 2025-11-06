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

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

type ClusterMonitoringOperatorTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewClusterMonitoringOperatorTask(
	client *client.Client,
	factory *manifests.Factory,
	config *manifests.Config,
) *ClusterMonitoringOperatorTask {
	return &ClusterMonitoringOperatorTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *ClusterMonitoringOperatorTask) Run(ctx context.Context) error {
	for name, crf := range map[string]func() (*rbacv1.ClusterRole, error){
		"cluster-monitoring-view":          t.factory.ClusterMonitoringClusterRoleView,
		"system:aggregated-metrics-reader": t.factory.ClusterMonitoringClusterRoleAggregatedMetricsReader,
		"pod-metrics-reader":               t.factory.ClusterMonitoringClusterRolePodMetricsReader,
		"monitoring-rules-edit":            t.factory.ClusterMonitoringRulesEditClusterRole,
		"monitoring-rules-view":            t.factory.ClusterMonitoringRulesViewClusterRole,
		"monitoring-edit":                  t.factory.ClusterMonitoringEditClusterRole,
		"alert-routing-edit":               t.factory.ClusterMonitoringAlertingEditClusterRole,
	} {
		cr, err := crf()
		if err != nil {
			return fmt.Errorf("initializing %s ClusterRole failed: %w", name, err)
		}

		err = t.client.CreateOrUpdateClusterRole(ctx, cr)
		if err != nil {
			return fmt.Errorf("reconciling %s ClusterRole failed: %w", name, err)
		}
	}

	uwcr, err := t.factory.ClusterMonitoringEditUserWorkloadConfigRole()
	if err != nil {
		return fmt.Errorf("initializing UserWorkloadConfigEdit Role failed: %w", err)
	}

	err = t.client.CreateOrUpdateRole(ctx, uwcr)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkloadConfigEdit Role failed: %w", err)
	}

	uwar, err := t.factory.ClusterMonitoringEditUserWorkloadAlertmanagerApiReader()
	if err != nil {
		return fmt.Errorf("initializing UserWorkloadAlertmanagerApiReader Role failed: %w", err)
	}

	err = t.client.CreateOrUpdateRole(ctx, uwar)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkloadAlertmanagerApiReader Role failed: %w", err)
	}

	uwaw, err := t.factory.ClusterMonitoringEditUserWorkloadAlertmanagerApiWriter()
	if err != nil {
		return fmt.Errorf("initializing UserWorkloadAlertmanagerApiWriter Role failed: %w", err)
	}

	err = t.client.CreateOrUpdateRole(ctx, uwaw)
	if err != nil {
		return fmt.Errorf("reconciling UserWorkloadAlertmanagerApiWriter Role failed: %w", err)
	}

	amrr, err := t.factory.ClusterMonitoringAlertManagerViewRole()
	if err != nil {
		return fmt.Errorf("initializing AlertmanagerRead Role failed: %w", err)
	}

	amwr, err := t.factory.ClusterMonitoringAlertManagerEditRole()
	if err != nil {
		return fmt.Errorf("initializing AlertmanagerWrite Role failed: %w", err)
	}

	if t.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.IsEnabled() {
		if err = t.client.CreateOrUpdateRole(ctx, amwr); err != nil {
			return fmt.Errorf("reconciling AlertmanagerWrite Role failed: %w", err)
		}
		if err = t.client.CreateOrUpdateRole(ctx, amrr); err != nil {
			return fmt.Errorf("reconciling AlertmanagerRead Role failed: %w", err)
		}
	} else {
		if err = t.client.DeleteRole(ctx, amwr); err != nil {
			return fmt.Errorf("deleting AlertmanagerWrite Role failed: %w", err)
		}
		if err = t.client.DeleteRole(ctx, amrr); err != nil {
			return fmt.Errorf("deleting AlertmanagerRead Role failed: %w", err)
		}
	}

	clarr, err := t.factory.ClusterMonitoringApiReaderRole()
	if err != nil {
		return fmt.Errorf("initializing ClusterMonitoringApiReader Role failed: %w", err)
	}

	err = t.client.CreateOrUpdateRole(ctx, clarr)
	if err != nil {
		return fmt.Errorf("reconciling ClusterMonitoringApiReader Role failed: %w", err)
	}

	pr, err := t.factory.ClusterMonitoringOperatorPrometheusRule()
	if err != nil {
		return fmt.Errorf("initializing cluster-monitoring-operator rules PrometheusRule failed: %w", err)
	}
	err = t.client.CreateOrUpdatePrometheusRule(ctx, pr)
	if err != nil {
		return fmt.Errorf("reconciling cluster-monitoring-operator rules PrometheusRule failed: %w", err)
	}

	smcmo, err := t.factory.ClusterMonitoringOperatorServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing Cluster Monitoring Operator ServiceMonitor failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smcmo)
	if err != nil {
		return fmt.Errorf("reconciling Cluster Monitoring Operator ServiceMonitor failed: %w", err)
	}

	s, err := t.factory.GRPCSecret()
	if err != nil {
		return fmt.Errorf("error initializing Cluster Monitoring Operator GRPC TLS secret: %w", err)
	}

	loaded, err := t.client.GetSecret(ctx, s.Namespace, s.Name)
	switch {
	case apierrors.IsNotFound(err):
		// No secret was found, proceed with the default empty secret from manifests.
		klog.V(5).Info("creating new Cluster Monitoring Operator GRPC TLS secret")
	case err == nil:
		// Secret was found, use that.
		s = loaded
		klog.V(5).Info("found existing Cluster Monitoring Operator GRPC TLS secret")
	default:
		return fmt.Errorf("error reading Cluster Monitoring Operator GRPC TLS secret: %w", err)
	}

	err = manifests.RotateGRPCSecret(s)
	if err != nil {
		return fmt.Errorf("error rotating Cluster Monitoring Operator GRPC TLS secret: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, s)
	if err != nil {
		return fmt.Errorf("error creating Cluster Monitoring Operator GRPC TLS secret: %w", err)
	}

	return nil
}
