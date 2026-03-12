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

package manifests

import (
	"errors"
	"fmt"

	v1 "k8s.io/api/core/v1"
	jsonutil "k8s.io/apimachinery/pkg/util/json"
	"k8s.io/klog/v2"
	kjson "sigs.k8s.io/json"
	kyaml "sigs.k8s.io/yaml"
)

// UnmarshalStrict is copied from k8s.io/apimachinery/pkg/util/yaml but uses
// sigs.k8s.io/json.UnmarshalStrict for case-sensitive unmarshalling and better errors.
func UnmarshalStrict(data []byte, v interface{}) error {
	unmarshalStrict := func(yamlBytes []byte, obj interface{}) error {
		jsonBytes, err := kyaml.YAMLToJSONStrict(yamlBytes)
		if err != nil {
			return err
		}
		strictErrs, err := kjson.UnmarshalStrict(jsonBytes, obj)
		if err != nil {
			return fmt.Errorf("error unmarshaling: %w", err)
		}
		if len(strictErrs) != 0 {
			return fmt.Errorf("error unmarshaling: %w", errors.Join(strictErrs...))
		}
		return nil
	}
	// Kept for backward compatibility.
	switch v := v.(type) {
	case *map[string]interface{}:
		if err := unmarshalStrict(data, v); err != nil {
			return err
		}
		return jsonutil.ConvertMapNumbers(*v, 0)
	case *[]interface{}:
		if err := unmarshalStrict(data, v); err != nil {
			return err
		}
		return jsonutil.ConvertSliceNumbers(*v, 0)
	case *interface{}:
		if err := unmarshalStrict(data, v); err != nil {
			return err
		}
		return jsonutil.ConvertInterfaceNumbers(v, 0)
	default:
		return unmarshalStrict(data, v)
	}
}

func newConfig(content []byte) (*Config, error) {
	c := Config{}

	cmc := defaultClusterMonitoringConfiguration()
	err := UnmarshalStrict(content, &cmc)
	if err != nil {
		return nil, err
	}

	c.ClusterMonitoringConfiguration = &cmc
	c.applyDefaults()
	c.UserWorkloadConfiguration = NewDefaultUserWorkloadMonitoringConfig()

	return &c, nil
}

// NewConfigFromString transforms a string containing configuration in the
// openshift-monitoring/cluster-monitoring-configuration format into a data
// structure that facilitates programmatical checks of that configuration. The
// content of the data structure might change if TechPreview is enabled (tp), as
// some features are only meant for TechPreview.
func NewConfigFromString(content string) (*Config, error) {
	if content == "" {
		return NewDefaultConfig(), nil
	}

	return newConfig([]byte(content))
}

func NewConfigFromConfigMap(c *v1.ConfigMap) (*Config, error) {
	configContent, found := c.Data[configKey]

	if !found {
		return nil, fmt.Errorf("%q key not found in the configmap", configKey)
	}

	cParsed, err := NewConfigFromString(configContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse data at key %q: %w", configKey, err)
	}
	return cParsed, nil
}

func NewDefaultConfig() *Config {
	c := &Config{}
	cmc := defaultClusterMonitoringConfiguration()
	c.ClusterMonitoringConfiguration = &cmc
	c.UserWorkloadConfiguration = NewDefaultUserWorkloadMonitoringConfig()
	c.applyDefaults()
	return c
}

func NewUserConfigFromString(content string) (*UserWorkloadConfiguration, error) {
	if content == "" {
		return NewDefaultUserWorkloadMonitoringConfig(), nil
	}

	u := &UserWorkloadConfiguration{}
	err := UnmarshalStrict([]byte(content), &u)
	if err != nil {
		return nil, err
	}

	u.applyDefaults()

	if err := u.check(); err != nil {
		return nil, err
	}

	return u, nil
}

func NewUserWorkloadConfigFromConfigMap(c *v1.ConfigMap) (*UserWorkloadConfiguration, error) {
	configContent, found := c.Data[configKey]

	if !found {
		klog.Warningf("the user workload monitoring configmap does not contain the %q key", configKey)
		return NewDefaultUserWorkloadMonitoringConfig(), nil
	}

	uwc, err := NewUserConfigFromString(configContent)
	if err != nil {
		return nil, fmt.Errorf("the user workload monitoring configuration in %q could not be parsed: %w", configKey, err)
	}
	return uwc, nil
}

func NewDefaultUserWorkloadMonitoringConfig() *UserWorkloadConfiguration {
	u := &UserWorkloadConfiguration{}
	u.applyDefaults()
	return u
}
