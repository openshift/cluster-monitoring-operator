package manifests

import (
	"fmt"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
)

// PrometheusAdditionalAlertmanagerConfigs is a AdditionalAlertmanagerConfig slice
type PrometheusAdditionalAlertmanagerConfigs []AdditionalAlertmanagerConfig

// MarshalYAML implements the yaml.Marshaler interface.
func (a PrometheusAdditionalAlertmanagerConfigs) MarshalYAML() (interface{}, error) {
	result := make([]interface{}, len(a))

	for i, item := range a {
		promAmCfg := prometheusAdditionalAlertmanagerConfig(item)

		y, err := promAmCfg.MarshalYAML()
		if err != nil {
			return nil, errors.Wrapf(err, "additional Alertmanager configuration[%d]", i)
		}

		result[i] = y
	}

	return result, nil
}

// amConfigPrometheus is our internal representation of the Prometheus alerting configuration.
type amConfigPrometheus struct {
	Scheme        string                  `yaml:"scheme,omitempty"`
	PathPrefix    string                  `yaml:"path_prefix,omitempty"`
	Timeout       *string                 `yaml:"timeout,omitempty"`
	APIVersion    string                  `yaml:"api_version,omitempty"`
	Authorization amConfigAuthorization   `yaml:"authorization,omitempty"`
	TLSConfig     amConfigTLS             `yaml:"tls_config,omitempty"`
	StaticConfigs []amConfigStaticConfigs `yaml:"static_configs,omitempty"`
}

type amConfigAuthorization struct {
	CredentialsFile string `yaml:"credentials_file"`
}

type amConfigTLS struct {
	CA                 string `yaml:"ca_file,omitempty"`
	Cert               string `yaml:"cert_file,omitempty"`
	Key                string `yaml:"key_file,omitempty"`
	ServerName         string `yaml:"server_name,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify,omitempty"`
}

type amConfigStaticConfigs struct {
	Targets []string `yaml:"targets"`
}

// prometheusAdditionalAlertmanagerConfig is an AdditionalAlertmanagerConfig
// which can be marshaled into a yaml string, compatible with the Prometheus
// configuration format
type prometheusAdditionalAlertmanagerConfig AdditionalAlertmanagerConfig

// MarshalYAML implements the yaml.Marshaler interface.
// It marshals a PrometheusAdditionalAlertmanagerConfig into a format
// compatible with the Prometheus configuration.
func (a prometheusAdditionalAlertmanagerConfig) MarshalYAML() (interface{}, error) {
	cfg := amConfigPrometheus{
		Scheme:     a.Scheme,
		PathPrefix: a.PathPrefix,
		Timeout:    a.Timeout,
		APIVersion: a.APIVersion,
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
}

type amHTTPConfig struct {
	BearerTokenFile string      `yaml:"bearer_token_file,omitempty"`
	TLSConfig       amConfigTLS `yaml:"tls_config,omitempty"`
}

func ConvertToThanosAlertmanagerConfiguration(ta []AdditionalAlertmanagerConfig) ([]thanosAlertmanagerConfiguration, error) {
	result := make([]thanosAlertmanagerConfiguration, len(ta))

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
		return errors.Errorf("secret %q not found", s.Name)
	}

	if s.Key == "" {
		return errors.Errorf("key %q for secret %q not found", s.Key, s.Name)
	}

	return nil
}
