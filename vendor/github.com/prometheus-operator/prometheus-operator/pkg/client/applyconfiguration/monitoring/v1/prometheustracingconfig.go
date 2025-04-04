// Copyright The prometheus-operator Authors
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

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	resource "k8s.io/apimachinery/pkg/api/resource"
)

// PrometheusTracingConfigApplyConfiguration represents a declarative configuration of the PrometheusTracingConfig type for use
// with apply.
type PrometheusTracingConfigApplyConfiguration struct {
	ClientType       *string                      `json:"clientType,omitempty"`
	Endpoint         *string                      `json:"endpoint,omitempty"`
	SamplingFraction *resource.Quantity           `json:"samplingFraction,omitempty"`
	Insecure         *bool                        `json:"insecure,omitempty"`
	Headers          map[string]string            `json:"headers,omitempty"`
	Compression      *string                      `json:"compression,omitempty"`
	Timeout          *monitoringv1.Duration       `json:"timeout,omitempty"`
	TLSConfig        *TLSConfigApplyConfiguration `json:"tlsConfig,omitempty"`
}

// PrometheusTracingConfigApplyConfiguration constructs a declarative configuration of the PrometheusTracingConfig type for use with
// apply.
func PrometheusTracingConfig() *PrometheusTracingConfigApplyConfiguration {
	return &PrometheusTracingConfigApplyConfiguration{}
}

// WithClientType sets the ClientType field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ClientType field is set to the value of the last call.
func (b *PrometheusTracingConfigApplyConfiguration) WithClientType(value string) *PrometheusTracingConfigApplyConfiguration {
	b.ClientType = &value
	return b
}

// WithEndpoint sets the Endpoint field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Endpoint field is set to the value of the last call.
func (b *PrometheusTracingConfigApplyConfiguration) WithEndpoint(value string) *PrometheusTracingConfigApplyConfiguration {
	b.Endpoint = &value
	return b
}

// WithSamplingFraction sets the SamplingFraction field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SamplingFraction field is set to the value of the last call.
func (b *PrometheusTracingConfigApplyConfiguration) WithSamplingFraction(value resource.Quantity) *PrometheusTracingConfigApplyConfiguration {
	b.SamplingFraction = &value
	return b
}

// WithInsecure sets the Insecure field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Insecure field is set to the value of the last call.
func (b *PrometheusTracingConfigApplyConfiguration) WithInsecure(value bool) *PrometheusTracingConfigApplyConfiguration {
	b.Insecure = &value
	return b
}

// WithHeaders puts the entries into the Headers field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Headers field,
// overwriting an existing map entries in Headers field with the same key.
func (b *PrometheusTracingConfigApplyConfiguration) WithHeaders(entries map[string]string) *PrometheusTracingConfigApplyConfiguration {
	if b.Headers == nil && len(entries) > 0 {
		b.Headers = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Headers[k] = v
	}
	return b
}

// WithCompression sets the Compression field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Compression field is set to the value of the last call.
func (b *PrometheusTracingConfigApplyConfiguration) WithCompression(value string) *PrometheusTracingConfigApplyConfiguration {
	b.Compression = &value
	return b
}

// WithTimeout sets the Timeout field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Timeout field is set to the value of the last call.
func (b *PrometheusTracingConfigApplyConfiguration) WithTimeout(value monitoringv1.Duration) *PrometheusTracingConfigApplyConfiguration {
	b.Timeout = &value
	return b
}

// WithTLSConfig sets the TLSConfig field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TLSConfig field is set to the value of the last call.
func (b *PrometheusTracingConfigApplyConfiguration) WithTLSConfig(value *TLSConfigApplyConfiguration) *PrometheusTracingConfigApplyConfiguration {
	b.TLSConfig = value
	return b
}
