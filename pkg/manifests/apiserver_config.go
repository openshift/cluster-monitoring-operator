// Copyright 2021 The Cluster Monitoring Operator Authors
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

import configv1 "github.com/openshift/api/config/v1"

var (
	// APIServerDefaultTLSCiphers are the default TLS ciphers for API servers
	APIServerDefaultTLSCiphers = configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers
	// APIServerDefaultMinTLSVersion is the default minimum TLS version for API servers
	APIServerDefaultMinTLSVersion = configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion
)

// APIServerConfig is the cluster-wide configuration for all API servers.
type APIServerConfig struct {
	*configv1.APIServer
}

// NewAPIServerConfig creates a new APIServerConfig
func NewAPIServerConfig(config *configv1.APIServer) *APIServerConfig {
	return &APIServerConfig{
		config,
	}
}

// TLSCiphers returns the TLS ciphers for the
// TLS security profile defined in the APIServerConfig.
func (c *APIServerConfig) TLSCiphers() []string {
	profile := c.getTLSProfile()
	if len(profile.Ciphers) == 0 {
		return APIServerDefaultTLSCiphers
	}
	return profile.Ciphers
}

// MinTLSVersion returns the minimum TLS version for the
// TLS security profile defined in the APIServerConfig.
func (c *APIServerConfig) MinTLSVersion() string {
	profile := c.getTLSProfile()
	if profile.MinTLSVersion == "" {
		return string(APIServerDefaultMinTLSVersion)
	}
	return string(profile.MinTLSVersion)
}

func (c *APIServerConfig) getTLSProfile() configv1.TLSProfileSpec {
	defaultProfile := *configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	if c == nil || c.APIServer == nil || c.Spec.TLSSecurityProfile == nil {
		return defaultProfile
	}

	profile := c.Spec.TLSSecurityProfile
	if profile.Type != configv1.TLSProfileCustomType {
		if tlsConfig, ok := configv1.TLSProfiles[profile.Type]; ok {
			return *tlsConfig
		}
		return defaultProfile
	}

	if profile.Custom != nil {
		return profile.Custom.TLSProfileSpec
	}

	return defaultProfile
}
