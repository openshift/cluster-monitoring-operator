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
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog/v2"
)

type ClusterMonitoringOperatorTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewClusterMonitoringOperatorTask(client *client.Client, factory *manifests.Factory) *ClusterMonitoringOperatorTask {
	return &ClusterMonitoringOperatorTask{
		client:  client,
		factory: factory,
	}
}

func (t *ClusterMonitoringOperatorTask) Run() error {
	svc, err := t.factory.ClusterMonitoringOperatorService()
	if err != nil {
		return errors.Wrap(err, "initializing Cluster Monitoring Operator Service failed")
	}

	err = t.client.CreateOrUpdateService(svc)
	if err != nil {
		return errors.Wrap(err, "reconciling Cluster Monitoring Operator Service failed")
	}

	for name, crf := range map[string]func() (*rbacv1.ClusterRole, error){
		"cluster-monitoring-view": t.factory.ClusterMonitoringClusterRole,
		"monitoring-rules-edit":   t.factory.ClusterMonitoringRulesEditClusterRole,
		"monitoring-rules-view":   t.factory.ClusterMonitoringRulesViewClusterRole,
		"monitoring-edit":         t.factory.ClusterMonitoringEditClusterRole,
	} {
		cr, err := crf()
		if err != nil {
			return errors.Wrapf(err, "initializing %s ClusterRole failed", name)
		}

		err = t.client.CreateOrUpdateClusterRole(cr)
		if err != nil {
			return errors.Wrapf(err, "reconciling %s ClusterRole failed", name)
		}
	}

	uwcr, err := t.factory.ClusterMonitoringEditUserWorkloadConfigRole()
	if err != nil {
		return errors.Wrap(err, "initializing UserWorkloadConfigEdit Role failed")
	}

	err = t.client.CreateOrUpdateRole(uwcr)
	if err != nil {
		return errors.Wrap(err, "reconciling UserWorkloadConfigEdit Role failed")
	}

	pr, err := t.factory.ClusterMonitoringOperatorPrometheusRule()
	if err != nil {
		return errors.Wrap(err, "initializing cluster-monitoring-operator rules PrometheusRule failed")
	}
	err = t.client.CreateOrUpdatePrometheusRule(pr)
	if err != nil {
		return errors.Wrap(err, "reconciling cluster-monitoring-operator rules PrometheusRule failed")
	}

	smcmo, err := t.factory.ClusterMonitoringOperatorServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Cluster Monitoring Operator ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smcmo)
	if err != nil {
		return errors.Wrap(err, "reconciling Cluster Monitoring Operator ServiceMonitor failed")
	}

	s, err := t.factory.GRPCSecret()
	if err != nil {
		return errors.Wrap(err, "error initializing Cluster Monitoring Operator GRPC TLS secret")
	}

	loaded, err := t.client.GetSecret(s.Namespace, s.Name)
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

	err = t.client.CreateOrUpdateSecret(s)
	if err != nil {
		return errors.Wrap(err, "error creating Cluster Monitoring Operator GRPC TLS secret")
	}

	return nil
}
