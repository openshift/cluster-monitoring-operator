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
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/klog/v2"
)

type PrometheusValidationTask struct {
	client     *client.Client
	prometheus *monv1.Prometheus
}

func NewPrometheusValidationTask(client *client.Client, prometheus *monv1.Prometheus) *PrometheusValidationTask {
	if prometheus == nil {
		klog.Warning("PrometheusValidationTask created with Prometheus set to nil")
	}

	return &PrometheusValidationTask{
		client:     client,
		prometheus: prometheus,
	}
}

func (t *PrometheusValidationTask) Run(ctx context.Context) *StateError {
	if t.prometheus == nil {
		klog.Warningf("PrometheusValidationTask not run since Prometheus set to nil")
		return nil
	}

	klog.V(4).Info("validate prometheus object")
	return t.client.ValidatePrometheus(ctx, t.prometheus)
}
