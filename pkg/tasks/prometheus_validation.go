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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

type PrometheusValidationTask struct {
	client     *client.Client
	prometheus *metav1.ObjectMeta
}

func NewPrometheusValidationTask(client *client.Client, metadata *metav1.ObjectMeta) *PrometheusValidationTask {
	if metadata == nil {
		klog.Warning("PrometheusValidationTask created with Prometheus set to nil")
	}

	return &PrometheusValidationTask{
		client:     client,
		prometheus: metadata,
	}
}

func (t *PrometheusValidationTask) Run(ctx context.Context) error {

	if t.prometheus == nil {
		klog.Warning("PrometheusValidationTask not run since Prometheus set to nil")
		return nil
	}

	p, err := t.client.WaitForPrometheusByNsName(ctx, t.prometheus)
	if err != nil {
		return err
	}

	klog.V(4).Info("validate prometheus object")
	return t.client.ValidatePrometheus(ctx, p)
}
