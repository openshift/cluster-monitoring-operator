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
	"github.com/pkg/errors"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog/v2"
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

func (t *ClusterMonitoringOperatorTask) Run(ctx context.Context) StateErrors {
	return toStateErrors(t.create(ctx))
}

func (t *ClusterMonitoringOperatorTask) create(ctx context.Context) error {
	for name, crf := range map[string]func() (*rbacv1.ClusterRole, error){
		"cluster-monitoring-view": t.factory.ClusterMonitoringClusterRoleView,
		"monitoring-rules-edit":   t.factory.ClusterMonitoringRulesEditClusterRole,
		"monitoring-rules-view":   t.factory.ClusterMonitoringRulesViewClusterRole,
		"monitoring-edit":         t.factory.ClusterMonitoringEditClusterRole,
		"alert-routing-edit":      t.factory.ClusterMonitoringAlertingEditClusterRole,
	} {
		cr, err := crf()
		if err != nil {
			return errors.Wrapf(err, "initializing %s ClusterRole failed", name)
		}

		err = t.client.CreateOrUpdateClusterRole(ctx, cr)
		if err != nil {
			return errors.Wrapf(err, "reconciling %s ClusterRole failed", name)
		}
	}

	uwcr, err := t.factory.ClusterMonitoringEditUserWorkloadConfigRole()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkloadConfigEdit Role failed")
	}

	err = t.client.CreateOrUpdateRole(ctx, uwcr)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkloadConfigEdit Role failed")
	}

	amwr, err := t.factory.ClusterMonitoringAlertManagerEditRole()
	if err != nil {
		return errors.Wrap(err, "initializing AlertmanagerWrite Role failed")
	}

	if t.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.IsEnabled() {
		if err = t.client.CreateOrUpdateRole(ctx, amwr); err != nil {
			return errors.Wrap(err, "reconciling Alertmanager Role failed")
		}
	} else {
		if err = t.client.DeleteRole(ctx, amwr); err != nil {
			return errors.Wrap(err, "deleting Alertmanager Role failed")
		}
	}

	pr, err := t.factory.ClusterMonitoringOperatorPrometheusRule()
	if err != nil {
		return errors.Wrap(err, "initializing cluster-monitoring-operator rules PrometheusRule failed")
	}
	err = t.client.CreateOrUpdatePrometheusRule(ctx, pr)
	if err != nil {
		return errors.Wrap(err, "reconciling cluster-monitoring-operator rules PrometheusRule failed")
	}

	smcmo, err := t.factory.ClusterMonitoringOperatorServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Cluster Monitoring Operator ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smcmo)
	if err != nil {
		return errors.Wrap(err, "reconciling Cluster Monitoring Operator ServiceMonitor failed")
	}

	s, err := t.factory.GRPCSecret()
	if err != nil {
		return errors.Wrap(err, "error initializing Cluster Monitoring Operator GRPC TLS secret")
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
		return errors.Wrap(err, "error reading Cluster Monitoring Operator GRPC TLS secret")
	}

	err = manifests.RotateGRPCSecret(s)
	if err != nil {
		return errors.Wrap(err, "error rotating Cluster Monitoring Operator GRPC TLS secret")
	}

	err = t.client.CreateOrUpdateSecret(ctx, s)
	if err != nil {
		return errors.Wrap(err, "error creating Cluster Monitoring Operator GRPC TLS secret")
	}

	return nil
}
