package manifests

import (
	"fmt"
	"net/url"

	"golang.org/x/net/http/httpproxy"
	yaml2 "gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
)

// PrometheusAdditionalAlertmanagerConfigs is a AdditionalAlertmanagerConfig slice
type PrometheusAdditionalAlertmanagerConfigs []AdditionalAlertmanagerConfig

// MarshalYAML implements the yaml.Marshaler interface.
func (a PrometheusAdditionalAlertmanagerConfigs) MarshalYAML() (interface{}, error) {
	return a.MarshalYAMLWithTLSConfig(nil, "")
}

// MarshalYAMLWithTLSConfig marshals the configs with the provided TLS configuration
func (a PrometheusAdditionalAlertmanagerConfigs) MarshalYAMLWithTLSConfig(cipherSuites []string, minTLSVersion string) (interface{}, error) {
	result := make([]interface{}, len(a))

	for i, item := range a {
		promAmCfg := prometheusAdditionalAlertmanagerConfigWithTLS{
			AdditionalAlertmanagerConfig: item,
			CipherSuites:                 cipherSuites,
			MinTLSVersion:                minTLSVersion,
		}

		y, err := promAmCfg.MarshalYAML()
		if err != nil {
			return nil, fmt.Errorf("additional Alertmanager configuration[%d]: %w", i, err)
		}

		result[i] = y
	}

	return result, nil
}

// MarshalPrometheusAdditionalAlertmanagerConfigs marshals the configs with secure TLS settings
func (f *Factory) MarshalPrometheusAdditionalAlertmanagerConfigs(amConfigs []AdditionalAlertmanagerConfig) ([]byte, error) {
	prometheusAmConfigs := PrometheusAdditionalAlertmanagerConfigs(amConfigs)

	// Handle nil APIServerConfig during cluster bootstrap - use secure defaults
	var cipherSuites []string
	var minTLSVersion string
	if f.APIServerConfig != nil {
		cipherSuites = f.APIServerConfig.TLSCiphers()
		minTLSVersion = f.APIServerConfig.MinTLSVersion()
	} else {
		// Use OpenShift Intermediate TLS profile defaults during bootstrap
		cipherSuites = APIServerDefaultTLSCiphers
		minTLSVersion = string(APIServerDefaultMinTLSVersion)
	}

	result, err := prometheusAmConfigs.MarshalYAMLWithTLSConfig(cipherSuites, minTLSVersion)
	if err != nil {
		return nil, err
	}

	return yaml2.Marshal(result)
}

// amConfigPrometheus is our internal representation of the Prometheus alerting configuration.
type amConfigPrometheus struct {
	Scheme               string                  `yaml:"scheme,omitempty"`
	PathPrefix           string                  `yaml:"path_prefix,omitempty"`
	Timeout              *string                 `yaml:"timeout,omitempty"`
	APIVersion           string                  `yaml:"api_version,omitempty"`
	Authorization        amConfigAuthorization   `yaml:"authorization,omitempty"`
	TLSConfig            amConfigTLS             `yaml:"tls_config,omitempty"`
	StaticConfigs        []amConfigStaticConfigs `yaml:"static_configs,omitempty"`
	ProxyFromEnvironment bool                    `yaml:"proxy_from_environment,omitempty"`
}

type amConfigAuthorization struct {
	CredentialsFile string `yaml:"credentials_file"`
}

type amConfigTLS struct {
	CA                 string   `yaml:"ca_file,omitempty"`
	Cert               string   `yaml:"cert_file,omitempty"`
	Key                string   `yaml:"key_file,omitempty"`
	ServerName         string   `yaml:"server_name,omitempty"`
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify,omitempty"`
	MinVersion         string   `yaml:"min_version,omitempty"`
	CipherSuites       []string `yaml:"cipher_suites,omitempty"`
}

type amConfigStaticConfigs struct {
	Targets []string `yaml:"targets"`
}

// prometheusAdditionalAlertmanagerConfigWithTLS is an AdditionalAlertmanagerConfig
// with TLS configuration that can be marshaled with secure cipher suites and min TLS version
type prometheusAdditionalAlertmanagerConfigWithTLS struct {
	AdditionalAlertmanagerConfig
	CipherSuites  []string
	MinTLSVersion string
}

// MarshalYAML implements the yaml.Marshaler interface.
func (a prometheusAdditionalAlertmanagerConfigWithTLS) MarshalYAML() (interface{}, error) {
	cfg := amConfigPrometheus{
		Scheme:               a.Scheme,
		PathPrefix:           a.PathPrefix,
		Timeout:              a.Timeout,
		APIVersion:           a.APIVersion,
		ProxyFromEnvironment: true,
		TLSConfig: amConfigTLS{
			CA:                 "",
			Cert:               "",
			Key:                "",
			ServerName:         a.TLSConfig.ServerName,
			InsecureSkipVerify: a.TLSConfig.InsecureSkipVerify,
		},
		Authorization: amConfigAuthorization{
			CredentialsFile: "",
		},
	}

	// Check if this configuration needs TLS security settings
	// Apply strict TLS only for HTTPS connections WITHOUT explicit TLS config
	// If explicit TLS config is provided, respect user's choices
	hasExplicitTLSConfig := a.TLSConfig.CA != nil || a.TLSConfig.Cert != nil || a.TLSConfig.Key != nil ||
		a.TLSConfig.ServerName != "" || a.TLSConfig.InsecureSkipVerify

	needsTLSSecuritySettings := a.Scheme == "https" && !hasExplicitTLSConfig

	// Apply TLS security settings only for HTTPS connections without explicit TLS config
	if needsTLSSecuritySettings {
		cfg.TLSConfig.MinVersion = a.MinTLSVersion
		cfg.TLSConfig.CipherSuites = a.CipherSuites
	}

	caPath, err := secretPath(a.TLSConfig.CA)
	if err != nil {
		return nil, err
	}
	cfg.TLSConfig.CA = caPath

	keyPath, err := secretPath(a.TLSConfig.Key)
	if err != nil {
		return nil, err
	}
	cfg.TLSConfig.Key = keyPath

	certPath, err := secretPath(a.TLSConfig.Cert)
	if err != nil {
		return nil, err
	}
	cfg.TLSConfig.Cert = certPath

	bearerTokenPath, err := secretPath(a.BearerToken)
	if err != nil {
		return nil, err
	}
	cfg.Authorization.CredentialsFile = bearerTokenPath

	cfg.StaticConfigs = []amConfigStaticConfigs{
		{
			Targets: a.StaticConfigs,
		},
	}

	return cfg, nil
}

// thanosAlertingConfiguration is our internal representation of the Thanos
// alerting configuration.
type thanosAlertingConfiguration struct {
	Alertmanagers []thanosAlertmanagerConfiguration `yaml:"alertmanagers"`
}

type thanosAlertmanagerConfiguration struct {
	Scheme        string       `yaml:"scheme,omitempty"`
	PathPrefix    string       `yaml:"path_prefix,omitempty"`
	Timeout       *string      `yaml:"timeout,omitempty"`
	APIVersion    string       `yaml:"api_version,omitempty"`
	HTTPConfig    amHTTPConfig `yaml:"http_config,omitempty"`
	StaticConfigs []string     `yaml:"static_configs,omitempty"`
	ProxyURL      string       `yaml:"proxy_url,omitempty"`
}

type amHTTPConfig struct {
	BearerTokenFile string      `yaml:"bearer_token_file,omitempty"`
	TLSConfig       amConfigTLS `yaml:"tls_config,omitempty"`
}

func (f *Factory) ConvertToThanosAlertmanagerConfiguration(ta []AdditionalAlertmanagerConfig) ([]thanosAlertmanagerConfiguration, error) {
	result := make([]thanosAlertmanagerConfiguration, len(ta))

	// Handle nil APIServerConfig during cluster bootstrap - use secure defaults
	var cipherSuites []string
	var minTLSVersion string
	if f.APIServerConfig != nil {
		cipherSuites = f.APIServerConfig.TLSCiphers()
		minTLSVersion = f.APIServerConfig.MinTLSVersion()
	} else {
		// Use OpenShift Intermediate TLS profile defaults during bootstrap
		cipherSuites = APIServerDefaultTLSCiphers
		minTLSVersion = string(APIServerDefaultMinTLSVersion)
	}

	for i, a := range ta {
		cfg := thanosAlertmanagerConfiguration{
			Scheme:     a.Scheme,
			PathPrefix: a.PathPrefix,
			Timeout:    a.Timeout,
			APIVersion: a.APIVersion,
			HTTPConfig: amHTTPConfig{
				BearerTokenFile: "",
				TLSConfig: amConfigTLS{
					CA:                 "",
					Cert:               "",
					Key:                "",
					ServerName:         a.TLSConfig.ServerName,
					InsecureSkipVerify: a.TLSConfig.InsecureSkipVerify,
				},
			},
		}

		// Check if this configuration needs TLS security settings
		// Apply strict TLS only for HTTPS connections WITHOUT explicit TLS config
		// If explicit TLS config is provided, respect user's choices
		hasExplicitTLSConfig := a.TLSConfig.CA != nil || a.TLSConfig.Cert != nil || a.TLSConfig.Key != nil ||
			a.TLSConfig.ServerName != "" || a.TLSConfig.InsecureSkipVerify

		needsTLSSecuritySettings := a.Scheme == "https" && !hasExplicitTLSConfig

		// Apply TLS security settings only for HTTPS connections without explicit TLS config
		if needsTLSSecuritySettings {
			cfg.HTTPConfig.TLSConfig.MinVersion = minTLSVersion
			cfg.HTTPConfig.TLSConfig.CipherSuites = cipherSuites
		}

		caPath, err := secretPath(a.TLSConfig.CA)
		if err != nil {
			return nil, err
		}
		cfg.HTTPConfig.TLSConfig.CA = caPath

		keyPath, err := secretPath(a.TLSConfig.Key)
		if err != nil {
			return nil, err
		}
		cfg.HTTPConfig.TLSConfig.Key = keyPath

		certPath, err := secretPath(a.TLSConfig.Cert)
		if err != nil {
			return nil, err
		}
		cfg.HTTPConfig.TLSConfig.Cert = certPath

		bearerTokenPath, err := secretPath(a.BearerToken)
		if err != nil {
			return nil, err
		}
		cfg.HTTPConfig.BearerTokenFile = bearerTokenPath

		cfg.StaticConfigs = a.StaticConfigs

		httpConfig := httpproxy.Config{
			HTTPProxy:  f.proxy.HTTPProxy(),
			HTTPSProxy: f.proxy.HTTPSProxy(),
			NoProxy:    f.proxy.NoProxy(),
		}

		proxyFunc := httpConfig.ProxyFunc()

		for _, host := range cfg.StaticConfigs {
			if host == "" {
				continue
			}

			u := &url.URL{
				Scheme: cfg.Scheme,
				Host:   host,
			}

			proxyURL, err := proxyFunc(u)
			if err != nil {
				return nil, err
			}

			// Assumes that all hosts share the same proxy policy
			if proxyURL != nil {
				cfg.ProxyURL = proxyURL.String()
				break
			}
		}

		result[i] = cfg
	}

	return result, nil
}

func secretPath(s *v1.SecretKeySelector) (string, error) {
	if s == nil {
		return "", nil
	}

	if err := validateSecret(s); err != nil {
		return "", err
	}

	return fmt.Sprintf("/etc/prometheus/secrets/%s/%s", s.Name, s.Key), nil
}

func validateSecret(s *v1.SecretKeySelector) error {
	if s == nil {
		return nil
	}

	if s.Name == "" {
		return fmt.Errorf("secret %q not found", s.Name)
	}

	if s.Key == "" {
		return fmt.Errorf("key %q for secret %q not found", s.Key, s.Name)
	}

	return nil
}
