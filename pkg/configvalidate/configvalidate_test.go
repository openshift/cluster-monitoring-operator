// Copyright 2024 The Cluster Monitoring Operator Authors
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

package configvalidate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestHandle(t *testing.T) {
	tests := []struct {
		name    string
		req     admission.Request
		allowed bool
		message string
	}{
		{
			name: "valid platform config",
			req: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Name:      "cluster-monitoring-config",
					Namespace: "openshift-monitoring",
					Resource: metav1.GroupVersionResource{
						Group:    "",
						Version:  "v1",
						Resource: "configmaps",
					},
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "v1",
							"kind": "ConfigMap",
							"metadata": {
								"name": "cluster-monitoring-config",
								"namespace": "openshift-monitoring"
							},
							"data": {
								"config.yaml": "{\"prometheusK8s\": {}}"
							}
						}`),
					},
				},
			},
			allowed: true,
		},
		{
			name: "invalid platform config",
			req: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Name:      "cluster-monitoring-config",
					Namespace: "openshift-monitoring",
					Resource: metav1.GroupVersionResource{
						Group:    "",
						Version:  "v1",
						Resource: "configmaps",
					},
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "v1",
							"kind": "ConfigMap",
							"metadata": {
								"name": "cluster-monitoring-config",
								"namespace": "openshift-monitoring"
							},
							"data": {
								"config.yaml": "{\"prometheus_operator\": {}}"
							}
						}`),
					},
				},
			},
			allowed: false,
			message: "the monitoring configuration in \"config.yaml\" could not be parsed: error unmarshaling JSON: while decoding JSON: json: unknown field \"prometheus_operator\"",
		},
		{
			name: "non monitoring configmap",
			req: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Name:      "foo",
					Namespace: "openshift-monitoring",
					Resource: metav1.GroupVersionResource{
						Group:    "",
						Version:  "v1",
						Resource: "configmaps",
					},
					Object: runtime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "v1",
							"kind": "ConfigMap",
							"metadata": {
								"name": "foo",
								"namespace": "openshift-monitoring"
							},
							"data": {
								"bar": "baz"
							}
						}`),
					},
				},
			},
			allowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := newConfigmapsValidator().Handle(context.Background(), tt.req)
			require.Equal(t, tt.allowed, res.Allowed)
			require.Equal(t, tt.message, res.Result.Message)
		})
	}
}
