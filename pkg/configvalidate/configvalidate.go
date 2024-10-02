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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

const (
	monitoringPlatformNamespace = "openshift-monitoring"
	monitoringPlatformConfigmap = "cluster-monitoring-config"
	monitoringUWMNamespace      = "openshift-user-workload-monitoring"
	monitoringUWMConfigmap      = "user-workload-monitoring-config"
)

type parseConfig func(c *corev1.ConfigMap) error

func configParser(collectionProfilesEnabled bool) parseConfig {
	return func(c *corev1.ConfigMap) error {
		_, err := manifests.NewConfigFromConfigMap(c, collectionProfilesEnabled)
		return err
	}
}

func uwmConfigParser() parseConfig {
	return func(c *corev1.ConfigMap) error {
		_, err := manifests.NewUserConfigFromConfigMap(c)
		return err
	}
}

type configmapsValidator struct {
	d admission.Decoder

	collectionProfilesEnabled bool
}

func newConfigmapsValidator() *configmapsValidator {
	return &configmapsValidator{d: admission.NewDecoder(runtime.NewScheme())}
}

func MustNewConfigmapsValidatorHandler(collectionProfilesEnabled bool) *http.Handler {
	hook := &admission.Webhook{
		Handler: newConfigmapsValidator(),
	}

	handler, err := admission.StandaloneWebhook(hook, admission.StandaloneOptions{})
	if err != nil {
		panic(err)
	}
	return &handler
}

func (v *configmapsValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	var parser parseConfig
	switch {
	case req.Namespace == monitoringPlatformNamespace && req.Name == monitoringPlatformConfigmap:
		parser = configParser(v.collectionProfilesEnabled)
	case req.Namespace == monitoringUWMNamespace && req.Name == monitoringUWMConfigmap:
		parser = uwmConfigParser()
	default:
		return admission.Allowed("")
	}

	var configmap corev1.ConfigMap
	if err := v.d.Decode(req, &configmap); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	err := parser(&configmap)
	if err != nil {
		return admission.Denied(err.Error())
	}

	return admission.Allowed("")
}
