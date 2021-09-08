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

// GetTLSCiphers returns the TLS ciphers for the
// TLS security profile defined in the APIServerConfig.
func (c *APIServerConfig) GetTLSCiphers() []string {
	profile := c.getTLSProfile()
	if profile.Ciphers == nil || len(profile.Ciphers) == 0 {
		return APIServerDefaultTLSCiphers
	}
	return profile.Ciphers
}

// GetMinTLSVersion returns the minimum TLS version for the
// TLS security profile defined in the APIServerConfig.
func (c *APIServerConfig) GetMinTLSVersion() configv1.TLSProtocolVersion {
	profile := c.getTLSProfile()
	if profile.MinTLSVersion == "" {
		return APIServerDefaultMinTLSVersion
	}
	return profile.MinTLSVersion
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
