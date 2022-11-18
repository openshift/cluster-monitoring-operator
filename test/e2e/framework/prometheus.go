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

package framework

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	routev1 "github.com/openshift/api/route/v1"
)

func (f Framework) MakePrometheusWithWebTLSRemoteReceive(name, tlsSecretName string) *monitoringv1.Prometheus {
	// This is not required in the Prometheus spec, but we inspect that value in
	// WaitForPrometheus. Omitting it causes this code to derefence a nil.
	replicas := int32(1)
	return &monitoringv1.Prometheus{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   f.Ns,
			Annotations: map[string]string{},
			Labels: map[string]string{
				E2eTestLabelName: E2eTestLabelValue,
			},
		},
		Spec: monitoringv1.PrometheusSpec{
			CommonPrometheusFields: monitoringv1.CommonPrometheusFields{
				Replicas:           &replicas,
				ServiceAccountName: "prometheus-k8s",
				Secrets:            []string{tlsSecretName},
				EnableFeatures:     []string{"remote-write-receiver"},
				Web: &monitoringv1.WebSpec{
					TLSConfig: &monitoringv1.WebTLSConfig{
						ClientCA: monitoringv1.SecretOrConfigMap{
							Secret: &v1.SecretKeySelector{
								LocalObjectReference: v1.LocalObjectReference{
									Name: tlsSecretName,
								},
								Key: "ca.crt",
							},
						},
						Cert: monitoringv1.SecretOrConfigMap{
							Secret: &v1.SecretKeySelector{
								LocalObjectReference: v1.LocalObjectReference{
									Name: tlsSecretName,
								},
								Key: "server.crt",
							},
						},
						KeySecret: v1.SecretKeySelector{
							LocalObjectReference: v1.LocalObjectReference{
								Name: tlsSecretName,
							},
							Key: "server.key",
						},
						ClientAuthType: "VerifyClientCertIfGiven",
					},
				},
			},
		},
	}
}

func (f Framework) MakePrometheusService(ns, name, group string, serviceType v1.ServiceType) *v1.Service {
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("prometheus-%s", name),
			Labels: map[string]string{
				"group":          group,
				E2eTestLabelName: E2eTestLabelValue,
			},
			Namespace: ns,
		},
		Spec: v1.ServiceSpec{
			Type: serviceType,
			Ports: []v1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromInt(9090),
				},
				{
					Name:       "https",
					Port:       443,
					TargetPort: intstr.FromInt(9090),
				},
			},
			Selector: map[string]string{
				"prometheus": name,
			},
		},
	}
}

func (f Framework) MakePrometheusServiceRoute(svc *v1.Service) *routev1.Route {
	return &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			// naming this after the service would make sense but route
			// names have limitations (length, character set), so
			// its hardcoded
			Name: "prometheusreceiver",
			Labels: map[string]string{
				E2eTestLabelName: E2eTestLabelValue,
			},
			Namespace: f.Ns,
		},
		Spec: routev1.RouteSpec{
			To: routev1.RouteTargetReference{
				Kind: "Service",
				Name: svc.Name,
			},
			TLS: &routev1.TLSConfig{
				Termination: routev1.TLSTerminationPassthrough,
			},
		},
	}
}
