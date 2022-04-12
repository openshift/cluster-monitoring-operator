// Copyright 2022 The Cluster Monitoring Operator Authors
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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
)

type PrometheusValidationTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewPrometheusValidationTask(client *client.Client, factory *manifests.Factory) *PrometheusValidationTask {
	return &PrometheusValidationTask{
		client:  client,
		factory: factory,
	}
}

func (t *PrometheusValidationTask) Run(ctx context.Context) error {
	b := client.StateErrorBuilder{}

	// NOTE: if prometheus object can't be created, use the default prometheus
	prom, err := t.factory.NewPrometheusK8s()
	if err != nil {
		b.AddUnknown(client.DegradedState, err.Error())
		return b.ToError()
	}

	promNsName := types.NamespacedName{
		Name:      prom.Name,
		Namespace: prom.Namespace,
	}

	p, err := t.client.GetPrometheusByNsName(ctx, promNsName)
	if err != nil {
		klog.V(4).Info("validate prometheus failed to get prometheus: ", err)
		b.AddError(err, client.UnavailableState)
		return b.ToError()
	}

	if err := t.client.ValidatePrometheus(ctx, p); err != nil {
		klog.V(4).ErrorS(err, "prometheus validation failed")
		b.AddError(err, client.DegradedState)
	}
	return b.ToError()
}
