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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"strings"

	"github.com/alecthomas/units"
	configv1 "github.com/openshift/api/config/v1"
	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/prometheus/common/model"
	v1 "k8s.io/api/core/v1"
	jsonutil "k8s.io/apimachinery/pkg/util/json"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	kjson "sigs.k8s.io/json"
	kyaml "sigs.k8s.io/yaml"

	"github.com/openshift/cluster-monitoring-operator/pkg/metrics"
)

const (
	DefaultRetentionValue = "15d"

	// Limit the body size from scrape queries
	// Assumptions: one node has in average 110 pods, each pod exposes 400 metrics, each metric is expressed by on average 250 bytes.
	// 1.5x the size for a safe margin,
	// minimal HA requires 3 nodes. it rounds to 47.2 MB (49,500,000 Bytes).
	minimalSizeLimit = 3 * 1.5 * 110 * 400 * 250

	// A value of Prometheusk8s.enforceBodySizeLimit,
	// meaning the limit will be automatically calculated based on cluster capacity.
	automaticBodySizeLimit = "automatic"

	configKey = "config.yaml"
)

var reservedPrometheusExternalLabels = []string{"prometheus", "prometheus_replica", "cluster"}

var lowestIntervalLimit, highestIntervalLimit model.Duration

func init() {
	var err error
	lowestIntervalLimit, err = model.ParseDuration("5s")
	if err != nil {
		panic(err)
	}

	highestIntervalLimit, err = model.ParseDuration("5m")
	if err != nil {
		panic(err)
	}
}

type InvalidConfigWarning struct {
	ConfigMap string
	Err       error
}

func (e *InvalidConfigWarning) Warning() string {
	return fmt.Sprintf("configuration in the %q ConfigMap is invalid and should be fixed: %s", e.ConfigMap, e.Err)
}

var errPrometheusAdapterDeprecated = errors.New("k8sPrometheusAdapter is deprecated and usage should be removed, use metricsServer instead")

type Config struct {
	Images      *Images `json:"-"`
	RemoteWrite bool    `json:"-"`

	ClusterMonitoringConfiguration *ClusterMonitoringConfiguration `json:"-"`
	UserWorkloadConfiguration      *UserWorkloadConfiguration      `json:"-"`
}

func (c Config) IsStorageConfigured() bool {
	if c.ClusterMonitoringConfiguration == nil {
		return false
	}

	prometheusK8sConfig := c.ClusterMonitoringConfiguration.PrometheusK8sConfig
	if prometheusK8sConfig == nil {
		return false
	}

	return prometheusK8sConfig.VolumeClaimTemplate != nil
}

func (c Config) HasInconsistentAlertmanagerConfigurations() bool {
	if c.ClusterMonitoringConfiguration == nil || c.UserWorkloadConfiguration == nil {
		return false
	}

	amConfig := c.ClusterMonitoringConfiguration.AlertmanagerMainConfig
	uwmConfig := c.UserWorkloadConfiguration.Alertmanager

	if amConfig == nil || uwmConfig == nil {
		return false
	}

	return amConfig.EnableUserAlertManagerConfig && uwmConfig.Enabled
}

// AdditionalAlertmanagerConfigsForPrometheusUserWorkload returns the alertmanager configurations for
// the User Workload Monitoring Prometheus instance.
// If no additional configurations are specified, GetPrometheusUWAdditionalAlertmanagerConfigs returns nil.
func (c Config) AdditionalAlertmanagerConfigsForPrometheusUserWorkload() []AdditionalAlertmanagerConfig {
	if c.UserWorkloadConfiguration == nil {
		return nil
	}

	if c.UserWorkloadConfiguration.Prometheus == nil {
		return nil
	}

	alertmanagerConfigs := c.UserWorkloadConfiguration.Prometheus.AlertmanagerConfigs
	if len(alertmanagerConfigs) == 0 {
		return nil
	}

	return alertmanagerConfigs
}

// GetThanosRulerAlertmanagerConfigs returns the alertmanager configurations for
// the User Workload Monitoring Thanos Ruler instance.
// If no additional configurations are specified, GetThanosRulerAlertmanagerConfigs returns nil.
func (c Config) GetThanosRulerAlertmanagerConfigs() []AdditionalAlertmanagerConfig {
	if c.UserWorkloadConfiguration == nil {
		return nil
	}

	if c.UserWorkloadConfiguration.ThanosRuler == nil {
		return nil
	}

	alertmanagerConfigs := c.UserWorkloadConfiguration.ThanosRuler.AlertmanagersConfigs
	if len(alertmanagerConfigs) == 0 {
		return nil
	}

	return alertmanagerConfigs
}

func checkIntervalValue(interval string) error {
	if interval == "" {
		return nil
	}

	d, err := model.ParseDuration(interval)
	if err != nil {
		return fmt.Errorf("invalid interval value: %w", err)
	}

	if (d < lowestIntervalLimit) || (d > highestIntervalLimit) {
		return fmt.Errorf("interval value %q outside of the allowed range [%q, %q]", interval, lowestIntervalLimit, highestIntervalLimit)
	}
	return nil
}

func (u *UserWorkloadConfiguration) validate() error {
	if u == nil {
		return nil
	}

	if err := checkIntervalValue(u.Prometheus.ScrapeInterval); err != nil {
		return fmt.Errorf("prometheus: scrape interval: %w", err)
	}

	if err := checkIntervalValue(u.Prometheus.EvaluationInterval); err != nil {
		return fmt.Errorf("prometheus: evaluation interval: %w", err)
	}

	if err := checkIntervalValue(u.ThanosRuler.EvaluationInterval); err != nil {
		return fmt.Errorf("thanos ruler: evaluation interval: %w", err)
	}

	if err := validateQueryLogFile(u.Prometheus.QueryLogFile); err != nil {
		return fmt.Errorf("prometheus: %w", err)
	}

	return nil
}

type Images struct {
	MetricsServer                      string
	PromLabelProxy                     string
	PrometheusOperatorAdmissionWebhook string
	PrometheusOperator                 string
	PrometheusConfigReloader           string
	Prometheus                         string
	Alertmanager                       string
	NodeExporter                       string
	KubeStateMetrics                   string
	OpenShiftStateMetrics              string
	KubeRbacProxy                      string
	TelemeterClient                    string
	Thanos                             string
	MonitoringPlugin                   string
	DebugTools                         string
}

type HTTPConfig struct {
	HTTPProxy  string `json:"httpProxy"`
	HTTPSProxy string `json:"httpsProxy"`
	NoProxy    string `json:"noProxy"`
}

func (a AlertmanagerMainConfig) IsEnabled() bool {
	return a.Enabled == nil || *a.Enabled
}

// Audit profile configurations
type Audit struct {
	// The Profile to set for audit logs. Supported values are
	// "Metadata", "Request", "RequestResponse" or "None".
	//
	// The default audit log level is "Metadata".
	//
	// see: https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#audit-policy
	// for more information about auditing and log levels.
	Profile auditv1.Level `json:"profile"`
}

func (cfg *TelemeterClientConfig) IsEnabled() bool {
	if cfg == nil {
		return false
	}

	if (cfg.Enabled != nil && !*cfg.Enabled) ||
		cfg.ClusterID == "" ||
		cfg.Token == "" {
		return false
	}

	return true
}

// Copied from k8s.io/apimachinery/pkg/util/yaml.UnmarshalStrict but using
// sigs.k8s.io/json.UnmarshalStrict instead of encoding/json.UnmarshalStrict
// to enforce case-sensitive unmarshalling and provide more detailed error context.
// This also allows for simpler error messages.
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

// NewConfigFromString returns the Config initialized from the provided string.
func NewConfigFromString(content string) (*Config, error) {
	return NewConfigFromStringAndClusterMonitoringResource(content, nil)
}

// NewConfigFromStringAndClusterMonitoringResource returns the Config
// initialized from the provided string and merged with the ClusterMonitoring
// resource.
func NewConfigFromStringAndClusterMonitoringResource(content string, cmr *configv1alpha1.ClusterMonitoring) (*Config, error) {
	cmc := ClusterMonitoringConfiguration{
		NodeExporterConfig: NodeExporterConfig{
			Collectors: NodeExporterCollectorConfig{
				NetDev: NodeExporterCollectorNetDevConfig{
					Enabled: true,
				},
				NetClass: NodeExporterCollectorNetClassConfig{
					Enabled:    true,
					UseNetlink: true,
				},
				Systemd: NodeExporterCollectorSystemdConfig{
					Enabled: false,
				},
			},
		},
	}

	err := UnmarshalStrict([]byte(content), &cmc)
	if err != nil {
		return nil, err
	}

	c := &Config{
		ClusterMonitoringConfiguration: &cmc,
		UserWorkloadConfiguration:      NewDefaultUserWorkloadMonitoringConfig(),
	}
	c.mergeClusterMonitoringCRD(cmr)

	c.applyDefaults()

	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigValidation, err)
	}

	return c, nil
}

func (c *Config) validate() error {
	if !slices.Contains(SupportedCollectionProfiles, c.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile) {
		return fmt.Errorf("%q is not supported, supported collection profiles are [%s]",
			c.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile,
			strings.Join(SupportedCollectionProfiles.StringSlice(), ", "),
		)
	}

	// Validate additional resource labels for KSM.
	if err := validateAdditionalResourceLabels(c.ClusterMonitoringConfiguration.KubeStateMetricsConfig); err != nil {
		return fmt.Errorf("kube-state-metrics: %w", err)
	}

	// Refer to https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#audit-policy
	// for the valid log levels.
	switch profile := c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit.Profile; profile {
	case auditv1.LevelNone,
		auditv1.LevelMetadata,
		auditv1.LevelRequest,
		auditv1.LevelRequestResponse:
	default:
		return fmt.Errorf("metrics server: audit profile %q not supported", profile)
	}

	if err := validateQueryLogFile(c.ClusterMonitoringConfiguration.PrometheusK8sConfig.QueryLogFile); err != nil {
		return fmt.Errorf("prometheus: %w", err)
	}

	return nil
}

// validateQueryLogFile validates the path of the Prometheus query log file.
//
// If not empty, the path should meet the following criteria:
// - the path is either an absolute path or a simple filename (in which case, the directory is ".").
// - the directory isn't the root directory.
// - if the directory is /dev, the path can only be /dev/stdout, /dev/stderr or /dev/null.
func validateQueryLogFile(path string) error {
	if path == "" {
		return nil
	}

	dirPath := filepath.Dir(path)
	if !filepath.IsAbs(path) && dirPath != "." {
		return errors.New("relative paths to query log file are not supported")
	}

	if dirPath == "/" {
		return errors.New("query log file can't be stored on the root directory")
	}

	if dirPath == "/dev" && path != "/dev/stdout" && path != "/dev/stderr" && path != "/dev/null" {
		return errors.New("query log file can't be stored on a new file on the dev directory")
	}

	return nil
}

var supportedResourceLabelsResources = []string{"jobs", "cronjobs"}

func validateAdditionalResourceLabels(ksm *KubeStateMetricsConfig) error {
	if ksm == nil {
		return nil
	}

	seenResources := map[string]bool{}
	for _, rl := range ksm.AdditionalResourceLabels {
		if rl.Resource == "" {
			return fmt.Errorf("%w: additionalResourceLabels: resource name must not be empty", ErrConfigValidation)
		}
		if !slices.Contains(supportedResourceLabelsResources, rl.Resource) {
			return fmt.Errorf("%w: additionalResourceLabels: unsupported resource %q, supported resources are: %v", ErrConfigValidation, rl.Resource, supportedResourceLabelsResources)
		}
		if seenResources[rl.Resource] {
			return fmt.Errorf("%w: additionalResourceLabels: duplicate resource %q", ErrConfigValidation, rl.Resource)
		}
		seenResources[rl.Resource] = true
		if len(rl.Labels) == 0 {
			return fmt.Errorf("%w: additionalResourceLabels: resource %q must have at least one label", ErrConfigValidation, rl.Resource)
		}
		if slices.Contains(rl.Labels, "") {
			return fmt.Errorf("%w: additionalResourceLabels: resource %q has an empty label value", ErrConfigValidation, rl.Resource)
		}
		seenLabels := map[string]bool{}
		for _, l := range rl.Labels {
			if seenLabels[l] {
				return fmt.Errorf("%w: additionalResourceLabels: resource %q has duplicate label %q", ErrConfigValidation, rl.Resource, l)
			}
			seenLabels[l] = true
		}
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.Images == nil {
		c.Images = &Images{}
	}

	if c.ClusterMonitoringConfiguration == nil {
		c.ClusterMonitoringConfiguration = &ClusterMonitoringConfiguration{}
	}

	if c.ClusterMonitoringConfiguration.UserWorkloadEnabled == nil {
		c.ClusterMonitoringConfiguration.UserWorkloadEnabled = ptr.To(false)
	}

	if c.ClusterMonitoringConfiguration.PrometheusOperatorConfig == nil {
		c.ClusterMonitoringConfiguration.PrometheusOperatorConfig = &PrometheusOperatorConfig{}
	}

	if c.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig == nil {
		c.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig = &PrometheusOperatorAdmissionWebhookConfig{}
	}

	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig == nil {
		c.ClusterMonitoringConfiguration.PrometheusK8sConfig = &PrometheusK8sConfig{}
	}

	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig.Retention == "" && c.ClusterMonitoringConfiguration.PrometheusK8sConfig.RetentionSize == "" {
		c.ClusterMonitoringConfiguration.PrometheusK8sConfig.Retention = DefaultRetentionValue
	}

	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile == "" {
		c.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile = FullCollectionProfile
	}

	if c.ClusterMonitoringConfiguration.AlertmanagerMainConfig == nil {
		c.ClusterMonitoringConfiguration.AlertmanagerMainConfig = &AlertmanagerMainConfig{}
	}

	if c.ClusterMonitoringConfiguration.UserWorkload == nil {
		c.ClusterMonitoringConfiguration.UserWorkload = &UserWorkloadConfig{}
	}

	if c.ClusterMonitoringConfiguration.UserWorkload.RulesWithoutLabelEnforcementAllowed == nil {
		c.ClusterMonitoringConfiguration.UserWorkload.RulesWithoutLabelEnforcementAllowed = ptr.To(true)
	}

	if c.ClusterMonitoringConfiguration.ThanosQuerierConfig == nil {
		c.ClusterMonitoringConfiguration.ThanosQuerierConfig = &ThanosQuerierConfig{}
	}

	if c.ClusterMonitoringConfiguration.KubeStateMetricsConfig == nil {
		c.ClusterMonitoringConfiguration.KubeStateMetricsConfig = &KubeStateMetricsConfig{}
	}

	if c.ClusterMonitoringConfiguration.OpenShiftMetricsConfig == nil {
		c.ClusterMonitoringConfiguration.OpenShiftMetricsConfig = &OpenShiftStateMetricsConfig{}
	}

	if c.ClusterMonitoringConfiguration.HTTPConfig == nil {
		c.ClusterMonitoringConfiguration.HTTPConfig = &HTTPConfig{}
	}

	if c.ClusterMonitoringConfiguration.TelemeterClientConfig == nil {
		c.ClusterMonitoringConfiguration.TelemeterClientConfig = &TelemeterClientConfig{
			TelemeterServerURL: "https://infogw.api.openshift.com/",
		}
	}

	if c.ClusterMonitoringConfiguration.MetricsServerConfig == nil {
		c.ClusterMonitoringConfiguration.MetricsServerConfig = &MetricsServerConfig{}
	}
	if c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit == nil {
		c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit = &Audit{}
	}
	if c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit.Profile == "" {
		c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit.Profile = auditv1.LevelMetadata
	}

	if c.ClusterMonitoringConfiguration.NodeExporterConfig.IgnoredNetworkDevices == nil {
		// `IgnoredNetworkDevices` is the default for two arguments:
		// `collector.netclass.ignored-devices` and
		// `--collector.netdev.device-exclude`.
		//
		// The following virtual NICs are ignored by default:
		// * `veth` network interface associated with containers.
		// * OVN renames `veth.*` to `<rand-hex>@if<X>` where `X` is `/sys/class/net/<if>/ifindex`
		// thus `[a-f0-9]{15}`
		// * `enP.*` virtual NICs on Azure cluster
		// * OVN virtual interfaces `ovn-k8s-mp[0-9]*`
		// * virtual tunnels and bridges: `tun[0-9]*|br[0-9]*|br-ex|br-int|br-ext`
		// * Calico Virtual NICs `cali[a-f0-9]*`
		// * bond devices
		//
		// Refer to:
		// https://issues.redhat.com/browse/OCPBUGS-1321
		// https://issues.redhat.com/browse/OCPBUGS-2729
		// https://issues.redhat.com/browse/OCPBUGS-7282
		// https://issues.redhat.com/browse/OCPBUGS-74347
		c.ClusterMonitoringConfiguration.NodeExporterConfig.IgnoredNetworkDevices = ptr.To([]string{
			"veth.*",
			"[a-f0-9]{15}",
			"enP.*",
			"ovn-k8s-mp[0-9]*",
			"br-ex",
			"br-int",
			"br-ext",
			"br[0-9]*",
			"tun[0-9]*",
			"cali[a-f0-9]*",
			"bond.*",
		})
	}
}

func (c *Config) SetImages(images map[string]string) {
	c.Images.PrometheusOperatorAdmissionWebhook = images["prometheus-operator-admission-webhook"]
	c.Images.PrometheusOperator = images["prometheus-operator"]
	c.Images.PrometheusConfigReloader = images["prometheus-config-reloader"]
	c.Images.Prometheus = images["prometheus"]
	c.Images.Alertmanager = images["alertmanager"]
	c.Images.NodeExporter = images["node-exporter"]
	c.Images.KubeStateMetrics = images["kube-state-metrics"]
	c.Images.KubeRbacProxy = images["kube-rbac-proxy"]
	c.Images.TelemeterClient = images["telemeter-client"]
	c.Images.PromLabelProxy = images["prom-label-proxy"]
	c.Images.MetricsServer = images["kube-metrics-server"]
	c.Images.OpenShiftStateMetrics = images["openshift-state-metrics"]
	c.Images.Thanos = images["thanos"]
	c.Images.MonitoringPlugin = images["monitoring-plugin"]
	c.Images.DebugTools = images["debug-tools"]
}

func (c *Config) SetTelemetryMatches(matches []string) {
	c.ClusterMonitoringConfiguration.PrometheusK8sConfig.TelemetryMatches = matches
}

func (c *Config) SetRemoteWrite(rw bool) {
	c.RemoteWrite = rw
	if c.RemoteWrite && c.ClusterMonitoringConfiguration.TelemeterClientConfig.TelemeterServerURL == "https://infogw.api.openshift.com/" {
		c.ClusterMonitoringConfiguration.TelemeterClientConfig.TelemeterServerURL = "https://infogw.api.openshift.com/metrics/v1/receive"
	}
}

func (c *Config) LoadClusterID(load func() (*configv1.ClusterVersion, error)) error {
	if c.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID != "" {
		return nil
	}

	cv, err := load()
	if err != nil {
		return fmt.Errorf("error loading cluster version: %w", err)
	}

	c.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID = string(cv.Spec.ClusterID)
	return nil
}

func (c *Config) LoadToken(load func() (*v1.Secret, error)) error {
	if c.ClusterMonitoringConfiguration.TelemeterClientConfig.Token != "" {
		return nil
	}

	secret, err := load()
	if err != nil {
		return fmt.Errorf("error loading secret: %w", err)
	}

	if secret.Type != v1.SecretTypeDockerConfigJson {
		return fmt.Errorf("error expecting secret type %s got %s", v1.SecretTypeDockerConfigJson, secret.Type)
	}

	ps := struct {
		Auths struct {
			COC struct {
				Auth string `json:"auth"`
			} `json:"cloud.openshift.com"`
		} `json:"auths"`
	}{}

	if err := json.Unmarshal(secret.Data[v1.DockerConfigJsonKey], &ps); err != nil {
		return fmt.Errorf("unmarshaling pull secret failed: %w", err)
	}

	c.ClusterMonitoringConfiguration.TelemeterClientConfig.Token = ps.Auths.COC.Auth
	return nil
}

// HTTPProxy implements the ProxyReader interface.
func (c *Config) HTTPProxy() string {
	return c.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy
}

// HTTPSProxy implements the ProxyReader interface.
func (c *Config) HTTPSProxy() string {
	return c.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy
}

// NoProxy implements the ProxyReader interface.
func (c *Config) NoProxy() string {
	return c.ClusterMonitoringConfiguration.HTTPConfig.NoProxy
}

// PodCapacityReader returns the maximum number of pods that can be scheduled in a cluster.
type PodCapacityReader interface {
	PodCapacity(context.Context) (int, error)
}

func (c *Config) LoadEnforcedBodySizeLimit(pcr PodCapacityReader, ctx context.Context) error {
	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit == "" {
		return nil
	}

	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit == automaticBodySizeLimit {
		podCapacity, err := pcr.PodCapacity(ctx)
		if err != nil {
			return fmt.Errorf("error fetching pod capacity: %w", err)
		}
		c.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit = calculateBodySizeLimit(podCapacity)
		return nil
	}

	// To validate if given value is parsable for the acceptable size values
	if _, err := units.ParseBase2Bytes(c.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit); err != nil {
		return err
	}

	return nil
}

func (c *Config) CheckDeprecatedFields() []InvalidConfigWarning {
	// Prometheus-Adapter is replaced with Metrics Server by default from 4.16
	var d float64
	var warnings []InvalidConfigWarning
	if c.ClusterMonitoringConfiguration.K8sPrometheusAdapter != nil {
		klog.Infof("k8sPrometheusAdapter is a deprecated config use metricsServer instead")
		d = 1
		warnings = append(warnings, InvalidConfigWarning{ConfigMap: "openshift-monitoring/cluster-monitoring-config", Err: errPrometheusAdapterDeprecated})
	}
	metrics.DeprecatedConfig.WithLabelValues("openshift-monitoring/cluster-monitoring-config", "k8sPrometheusAdapter", "4.16").Set(d)

	return warnings
}

func calculateBodySizeLimit(podCapacity int) string {
	const samplesPerPod = 400 // 400 samples per pod
	const sizePerSample = 200 // 200 Bytes

	bodySize := podCapacity * samplesPerPod * sizePerSample
	if bodySize < minimalSizeLimit {
		klog.Infof("Calculated scrape body size limit %v is too small, using default value %v instead", bodySize, minimalSizeLimit)
		bodySize = minimalSizeLimit
	}

	return fmt.Sprintf("%dMB", int(math.Ceil(float64(bodySize)/(1024*1024))))
}

// NewConfigFromConfigMap returns the Config initialized from the provided ConfigMap.
func NewConfigFromConfigMap(c *v1.ConfigMap) (*Config, error) {
	return NewConfigFromConfigMapAndClusterMonitoringResource(c, nil)
}

// NewConfigFromConfigMapAndClusterMonitoringResource returns the Config
// initialized from the provided ConfigMap and merged with the
// ClusterMonitoring resource.
func NewConfigFromConfigMapAndClusterMonitoringResource(c *v1.ConfigMap, cmr *configv1alpha1.ClusterMonitoring) (*Config, error) {
	configContent, found := c.Data[configKey]
	if !found {
		return nil, fmt.Errorf("%q key not found in the configmap", configKey)
	}

	if configContent == "" {
		// Consider an empty string to be equivalent to an empty map.
		configContent = "{}"
	}

	cParsed, err := NewConfigFromStringAndClusterMonitoringResource(configContent, cmr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse data at key %q: %w", configKey, err)
	}
	return cParsed, nil
}

func (u *UserWorkloadConfiguration) applyDefaults() {
	if u.PrometheusOperator == nil {
		u.PrometheusOperator = &PrometheusOperatorConfig{}
	}

	if u.Prometheus == nil {
		u.Prometheus = &PrometheusRestrictedConfig{}
	}

	if u.ThanosRuler == nil {
		u.ThanosRuler = &ThanosRulerConfig{}
	}

	// If the user configured a retention for user-workload Prometheus but did not
	// explicitly set a retention for Thanos Ruler, default Thanos Ruler retention
	// to the same value as Prometheus. This keeps the effective retention aligned
	// unless the user overrides it for Thanos Ruler.
	if u.ThanosRuler.Retention == "" && u.Prometheus != nil && u.Prometheus.Retention != "" {
		u.ThanosRuler.Retention = u.Prometheus.Retention
	}

	if u.Alertmanager == nil {
		u.Alertmanager = &AlertmanagerUserWorkloadConfig{}
	}
}

func NewUserConfigFromString(content string) (*UserWorkloadConfiguration, error) {
	if content == "" {
		// Consider an empty string to be equivalent to an empty map.
		content = "{}"
	}

	u := &UserWorkloadConfiguration{}
	err := UnmarshalStrict([]byte(content), &u)
	if err != nil {
		return nil, err
	}

	u.applyDefaults()

	if err := u.validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigValidation, err)
	}

	return u, nil
}

func NewUserWorkloadConfigFromConfigMap(c *v1.ConfigMap) (*UserWorkloadConfiguration, error) {
	configContent, found := c.Data[configKey]
	if !found {
		klog.Warningf("the user workload monitoring configmap does not contain the %q key", configKey)
	}

	uwc, err := NewUserConfigFromString(configContent)
	if err != nil {
		return nil, fmt.Errorf("the user workload monitoring configuration in %q could not be parsed: %w", configKey, err)
	}

	return uwc, nil
}

func NewDefaultUserWorkloadMonitoringConfig() *UserWorkloadConfiguration {
	u, err := NewUserConfigFromString("{}")
	if err != nil {
		// Should never happen.
		panic(err)
	}

	return u
}

func (lb *ExternalLabels) UnmarshalJSON(data []byte) error {
	var v map[string]string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	for _, r := range reservedPrometheusExternalLabels {
		if _, ok := v[r]; ok {
			// We’re assuming that the field is called "externalLabels", that's all the context we can easily provide.
			return fmt.Errorf("reserved key %q (one of %v) cannot be set in externalLabels", r, reservedPrometheusExternalLabels)
		}
	}
	*lb = v
	return nil
}
