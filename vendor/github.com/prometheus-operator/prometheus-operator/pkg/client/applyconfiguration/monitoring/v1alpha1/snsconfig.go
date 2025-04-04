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

package v1alpha1

import (
	v1 "github.com/prometheus-operator/prometheus-operator/pkg/client/applyconfiguration/monitoring/v1"
)

// SNSConfigApplyConfiguration represents a declarative configuration of the SNSConfig type for use
// with apply.
type SNSConfigApplyConfiguration struct {
	SendResolved *bool                         `json:"sendResolved,omitempty"`
	ApiURL       *string                       `json:"apiURL,omitempty"`
	Sigv4        *v1.Sigv4ApplyConfiguration   `json:"sigv4,omitempty"`
	TopicARN     *string                       `json:"topicARN,omitempty"`
	Subject      *string                       `json:"subject,omitempty"`
	PhoneNumber  *string                       `json:"phoneNumber,omitempty"`
	TargetARN    *string                       `json:"targetARN,omitempty"`
	Message      *string                       `json:"message,omitempty"`
	Attributes   map[string]string             `json:"attributes,omitempty"`
	HTTPConfig   *HTTPConfigApplyConfiguration `json:"httpConfig,omitempty"`
}

// SNSConfigApplyConfiguration constructs a declarative configuration of the SNSConfig type for use with
// apply.
func SNSConfig() *SNSConfigApplyConfiguration {
	return &SNSConfigApplyConfiguration{}
}

// WithSendResolved sets the SendResolved field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SendResolved field is set to the value of the last call.
func (b *SNSConfigApplyConfiguration) WithSendResolved(value bool) *SNSConfigApplyConfiguration {
	b.SendResolved = &value
	return b
}

// WithApiURL sets the ApiURL field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ApiURL field is set to the value of the last call.
func (b *SNSConfigApplyConfiguration) WithApiURL(value string) *SNSConfigApplyConfiguration {
	b.ApiURL = &value
	return b
}

// WithSigv4 sets the Sigv4 field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Sigv4 field is set to the value of the last call.
func (b *SNSConfigApplyConfiguration) WithSigv4(value *v1.Sigv4ApplyConfiguration) *SNSConfigApplyConfiguration {
	b.Sigv4 = value
	return b
}

// WithTopicARN sets the TopicARN field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TopicARN field is set to the value of the last call.
func (b *SNSConfigApplyConfiguration) WithTopicARN(value string) *SNSConfigApplyConfiguration {
	b.TopicARN = &value
	return b
}

// WithSubject sets the Subject field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Subject field is set to the value of the last call.
func (b *SNSConfigApplyConfiguration) WithSubject(value string) *SNSConfigApplyConfiguration {
	b.Subject = &value
	return b
}

// WithPhoneNumber sets the PhoneNumber field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PhoneNumber field is set to the value of the last call.
func (b *SNSConfigApplyConfiguration) WithPhoneNumber(value string) *SNSConfigApplyConfiguration {
	b.PhoneNumber = &value
	return b
}

// WithTargetARN sets the TargetARN field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TargetARN field is set to the value of the last call.
func (b *SNSConfigApplyConfiguration) WithTargetARN(value string) *SNSConfigApplyConfiguration {
	b.TargetARN = &value
	return b
}

// WithMessage sets the Message field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Message field is set to the value of the last call.
func (b *SNSConfigApplyConfiguration) WithMessage(value string) *SNSConfigApplyConfiguration {
	b.Message = &value
	return b
}

// WithAttributes puts the entries into the Attributes field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Attributes field,
// overwriting an existing map entries in Attributes field with the same key.
func (b *SNSConfigApplyConfiguration) WithAttributes(entries map[string]string) *SNSConfigApplyConfiguration {
	if b.Attributes == nil && len(entries) > 0 {
		b.Attributes = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Attributes[k] = v
	}
	return b
}

// WithHTTPConfig sets the HTTPConfig field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the HTTPConfig field is set to the value of the last call.
func (b *SNSConfigApplyConfiguration) WithHTTPConfig(value *HTTPConfigApplyConfiguration) *SNSConfigApplyConfiguration {
	b.HTTPConfig = value
	return b
}
