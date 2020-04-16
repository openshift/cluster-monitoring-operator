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

	smcmo, err := t.factory.ClusterMonitoringOperatorServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Cluster Monitoring Operator ServiceMonitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(smcmo)
	if err != nil {
		return errors.Wrap(err, "reconciling Cluster Monitoring Operator ServiceMonitor failed")
	}

	s, err := t.client.GetSecret("openshift-monitoring", "grpc-tls")
	if apierrors.IsNotFound(err) {
		err = nil
		s = nil // this will be a zero value if it was not found
	}

	if err != nil {
		return errors.Wrap(err, "error reading Cluster Monitoring Operator GRPC TLS secret")
	}

	s, err = t.factory.GRPCSecret(s)
	if err != nil {
		return errors.Wrap(err, "error initializing Cluster Monitoring Operator GRPC TLS secret")
	}

	err = t.client.CreateOrUpdateSecret(s)
	if err != nil {
		return errors.Wrap(err, "error creating Cluster Monitoring Operator GRPC TLS secret")
	}

	return nil
}
