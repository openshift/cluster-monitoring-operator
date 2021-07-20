package manifests

import (
	"fmt"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
)

// PrometheusAdditionalAlertmanagerConfigs is a AdditionalAlertmanagerConfig slice
type PrometheusAdditionalAlertmanagerConfigs []AdditionalAlertmanagerConfig

// PrometheusAdditionalAlertmanagerConfig is an AdditionalAlertmanagerConfig
// which can be marshaled into a yaml string,
// compatible with the Prometheus configuration format
type PrometheusAdditionalAlertmanagerConfig AdditionalAlertmanagerConfig

func (a PrometheusAdditionalAlertmanagerConfigs) MarshalYAML() (interface{}, error) {
	result := make([]interface{}, len(a))
	for i, item := range a {
		promAmCfg := PrometheusAdditionalAlertmanagerConfig(item)
		if y, err := promAmCfg.MarshalYAML(); err != nil {
			return nil, errors.Wrapf(err, "additional Alertmanager configuration[%d]", i)
		} else {
			result[i] = y
		}
	}

	return result, nil
}

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

// MarshalYAML marshals a PrometheusAdditionalAlertmanagerConfig into
// a format compatible with the Prometheus configuration.
func (a PrometheusAdditionalAlertmanagerConfig) MarshalYAML() (interface{}, error) {
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
	if caPath, err := secretPath(a.TLSConfig.CA); err != nil {
		return nil, err
	} else {
		cfg.TLSConfig.CA = caPath
	}
	if keyPath, err := secretPath(a.TLSConfig.Key); err != nil {
		return nil, err
	} else {
		cfg.TLSConfig.Key = keyPath
	}
	if certPath, err := secretPath(a.TLSConfig.Cert); err != nil {
		return nil, err
	} else {
		cfg.TLSConfig.Cert = certPath
	}
	if bearerTokenPath, err := secretPath(a.BearerToken); err != nil {
		return nil, err
	} else {
		cfg.Authorization.CredentialsFile = bearerTokenPath
	}

	cfg.StaticConfigs = []amConfigStaticConfigs{
		{
			Targets: a.StaticConfigs,
		},
	}

	return cfg, nil
}

// ThanosAlertmanagerAdditionalConfigs is a AdditionalAlertmanagerConfig slice
type ThanosAlertmanagerAdditionalConfigs []AdditionalAlertmanagerConfig

// ThanosAlertmanagerAdditionalConfig is an AdditionalAlertmanagerConfig
// which can be marshaled into a yaml string,
// compatible with the Thanos configuration format
type ThanosAlertmanagerAdditionalConfig AdditionalAlertmanagerConfig

func (a ThanosAlertmanagerAdditionalConfigs) MarshalYAML() (interface{}, error) {
	result := make([]interface{}, len(a))
	for i, item := range a {
		promAmCfg := ThanosAlertmanagerAdditionalConfig(item)
		if y, err := promAmCfg.MarshalYAML(); err != nil {
			return nil, errors.Wrapf(err, "additional Alertmanager configuration[%d]", i)
		} else {
			result[i] = y
		}
	}

	return result, nil
}

type amConfigThanos struct {
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

// MarshalYAML marshals a ThanosAlertmanagerAdditionalConfig into
// a format compatible with the Prometheus configuration.
func (a ThanosAlertmanagerAdditionalConfig) MarshalYAML() (interface{}, error) {
	cfg := amConfigThanos{
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
	if caPath, err := secretPath(a.TLSConfig.CA); err != nil {
		return nil, err
	} else {
		cfg.HTTPConfig.TLSConfig.CA = caPath
	}
	if keyPath, err := secretPath(a.TLSConfig.Key); err != nil {
		return nil, err
	} else {
		cfg.HTTPConfig.TLSConfig.Key = keyPath
	}
	if certPath, err := secretPath(a.TLSConfig.Cert); err != nil {
		return nil, err
	} else {
		cfg.HTTPConfig.TLSConfig.Cert = certPath
	}
	if bearerTokenPath, err := secretPath(a.BearerToken); err != nil {
		return nil, err
	} else {
		cfg.HTTPConfig.BearerTokenFile = bearerTokenPath
	}

	cfg.StaticConfigs = a.StaticConfigs

	return cfg, nil
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
		return errors.Errorf("secret %q for ca not found", s.Name)
	}
	if s.Key == "" {
		return errors.Errorf("secret key %q for ca not found", s.Key)
	}

	return nil
}
