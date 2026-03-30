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
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/pkg/metrics"
)

const (
	monitoringPlatformNamespace = "openshift-monitoring"
	monitoringPlatformConfigmap = "cluster-monitoring-config"
	monitoringUWMNamespace      = "openshift-user-workload-monitoring"
	monitoringUWMConfigmap      = "user-workload-monitoring-config"
)

type parserFunc func(c *corev1.ConfigMap) error

type configmapsValidator struct {
	d admission.Decoder
}

func newConfigmapsValidator() *configmapsValidator {
	return &configmapsValidator{d: admission.NewDecoder(runtime.NewScheme())}
}

func MustNewConfigmapsValidatorHandler(path string) http.Handler {
	hook := &admission.Webhook{
		Handler: newConfigmapsValidator(),
	}

	handler, err := admission.StandaloneWebhook(hook, admission.StandaloneOptions{})
	if err != nil {
		panic(err)
	}

	lbl := prometheus.Labels{"webhook": path}
	lat := metrics.WebhookRequestLatency.MustCurryWith(lbl)
	cnt := metrics.WebhookRequestTotal.MustCurryWith(lbl)
	gge := metrics.WebhookRequestInFlight.With(lbl)

	// Initialize the most likely HTTP status codes.
	_ = cnt.WithLabelValues("200")
	_ = cnt.WithLabelValues("500")

	return promhttp.InstrumentHandlerDuration(
		lat,
		promhttp.InstrumentHandlerCounter(
			cnt,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gge.Inc()
				defer gge.Dec()
				handler.ServeHTTP(w, r)
			}),
		),
	)
}

func (v *configmapsValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	var parser parserFunc
	switch {
	case req.Namespace == monitoringPlatformNamespace && req.Name == monitoringPlatformConfigmap:
		parser = func(c *corev1.ConfigMap) error {
			_, err := manifests.NewConfigFromConfigMap(c)
			return err
		}
	case req.Namespace == monitoringUWMNamespace && req.Name == monitoringUWMConfigmap:
		parser = func(c *corev1.ConfigMap) error {
			_, err := manifests.NewUserWorkloadConfigFromConfigMap(c)
			return err
		}
	default:
		// This should not happen because the ValidatingWebhookConfiguration is
		// configured to validate only CMO and UWM configmaps but fail safe in
		// case the invariant changes.
		return admission.Allowed("")
	}

	var configmap corev1.ConfigMap
	if err := v.d.Decode(req, &configmap); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	if err := parser(&configmap); err != nil {
		return admission.Denied(err.Error())
	}

	return admission.Allowed("")
}
