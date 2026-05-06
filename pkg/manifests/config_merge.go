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
	"strings"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	yamlv3 "gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"k8s.io/utils/ptr"
)

// mergeClusterMonitoringCRD merges the ClusterMonitoring CR spec into the ConfigMap-derived
// config when clusterMonitoring is non-nil. Phase 1 (pre-GA): for each top-level field, if the
// ConfigMap did not set it, use the CR; otherwise keep the ConfigMap and ignore the CR for that field.
func (c *Config) mergeClusterMonitoringCRD(clusterMonitoring *configv1alpha1.ClusterMonitoring, clusterMonitoringConfigYAML string) {
	if clusterMonitoring == nil {
		return
	}

	// User workload: use the CR only if the ConfigMap did not set enableUserWorkload.
	if c.ClusterMonitoringConfiguration.UserWorkloadEnabled == nil && clusterMonitoring.Spec.UserDefined.Mode != "" {
		c.ClusterMonitoringConfiguration.UserWorkloadEnabled = ptr.To(clusterMonitoring.Spec.UserDefined.Mode == configv1alpha1.UserDefinedNamespaceIsolated)
	}

	c.mergeMetricsServerConfiguration(clusterMonitoring.Spec.MetricsServerConfig)
	c.mergePrometheusOperatorConfiguration(clusterMonitoring.Spec.PrometheusOperatorConfig)
	c.mergeAlertmanagerConfiguration(clusterMonitoring.Spec.AlertmanagerConfig)
	c.mergeMonitoringPluginConfiguration(clusterMonitoring.Spec.MonitoringPluginConfig)
	c.mergeNodeExporterConfiguration(clusterMonitoringConfigYAML, clusterMonitoring.Spec.NodeExporterConfig)
}

// configMapYAMLDeclaresNodeExporter reports whether the cluster-monitoring-config body includes a
// top-level nodeExporter key (including explicit null). Phase 1: if set, the ConfigMap wins for
// the whole nodeExporter stanza and the ClusterMonitoring CR's nodeExporterConfig is ignored.
func configMapYAMLDeclaresNodeExporter(cmYAML string) bool {
	if strings.TrimSpace(cmYAML) == "" {
		return false
	}
	var root map[string]interface{}
	if err := yamlv3.Unmarshal([]byte(cmYAML), &root); err != nil {
		return false
	}
	_, ok := root["nodeExporter"]
	return ok
}

func clusterMonitoringNodeExporterCollectorsEmpty(col configv1alpha1.NodeExporterCollectorConfig) bool {
	if col.CpuFreq.CollectionPolicy != "" {
		return false
	}
	if col.TcpStat.CollectionPolicy != "" {
		return false
	}
	if col.Ethtool.CollectionPolicy != "" {
		return false
	}
	if col.NetDev.CollectionPolicy != "" {
		return false
	}
	if col.NetClass.CollectionPolicy != "" {
		return false
	}
	if col.BuddyInfo.CollectionPolicy != "" {
		return false
	}
	if col.MountStats.CollectionPolicy != "" {
		return false
	}
	if col.Ksmd.CollectionPolicy != "" {
		return false
	}
	if col.Processes.CollectionPolicy != "" {
		return false
	}
	if col.Systemd.CollectionPolicy != "" {
		return false
	}
	if col.Softirqs.CollectionPolicy != "" {
		return false
	}
	return true
}

// clusterMonitoringNodeExporterSpecEmpty reports whether the CR's nodeExporterConfig stanza
// contains no user-set field.
func clusterMonitoringNodeExporterSpecEmpty(nec configv1alpha1.NodeExporterConfig) bool {
	if len(nec.Resources) > 0 {
		return false
	}
	if nec.MaxProcs != 0 {
		return false
	}
	if nec.IgnoredNetworkDevices != nil {
		return false
	}
	if !clusterMonitoringNodeExporterCollectorsEmpty(nec.Collectors) {
		return false
	}
	return true
}

func nodeExporterCollectorEnabledFromPolicy(p configv1alpha1.NodeExporterCollectorCollectionPolicy) (enabled bool, set bool) {
	switch p {
	case configv1alpha1.NodeExporterCollectorCollectionPolicyCollect:
		return true, true
	case configv1alpha1.NodeExporterCollectorCollectionPolicyDoNotCollect:
		return false, true
	default:
		return false, false
	}
}

func mergeNodeExporterCollectorsFromCRD(dst *NodeExporterCollectorConfig, src configv1alpha1.NodeExporterCollectorConfig) {
	if enabled, set := nodeExporterCollectorEnabledFromPolicy(src.CpuFreq.CollectionPolicy); set {
		dst.CpuFreq.Enabled = enabled
	}
	if enabled, set := nodeExporterCollectorEnabledFromPolicy(src.TcpStat.CollectionPolicy); set {
		dst.TcpStat.Enabled = enabled
	}
	if enabled, set := nodeExporterCollectorEnabledFromPolicy(src.Ethtool.CollectionPolicy); set {
		dst.Ethtool.Enabled = enabled
	}
	if enabled, set := nodeExporterCollectorEnabledFromPolicy(src.NetDev.CollectionPolicy); set {
		dst.NetDev.Enabled = enabled
	}
	if enabled, set := nodeExporterCollectorEnabledFromPolicy(src.NetClass.CollectionPolicy); set {
		dst.NetClass.Enabled = enabled
		if enabled && src.NetClass.Collect.StatsGatherer != "" {
			dst.NetClass.UseNetlink = src.NetClass.Collect.StatsGatherer == configv1alpha1.NodeExporterNetclassStatsGathererNetlink
		}
	}
	if enabled, set := nodeExporterCollectorEnabledFromPolicy(src.BuddyInfo.CollectionPolicy); set {
		dst.BuddyInfo.Enabled = enabled
	}
	if enabled, set := nodeExporterCollectorEnabledFromPolicy(src.MountStats.CollectionPolicy); set {
		dst.MountStats.Enabled = enabled
	}
	if enabled, set := nodeExporterCollectorEnabledFromPolicy(src.Ksmd.CollectionPolicy); set {
		dst.Ksmd.Enabled = enabled
	}
	if enabled, set := nodeExporterCollectorEnabledFromPolicy(src.Processes.CollectionPolicy); set {
		dst.Processes.Enabled = enabled
	}
	if enabled, set := nodeExporterCollectorEnabledFromPolicy(src.Systemd.CollectionPolicy); set {
		dst.Systemd.Enabled = enabled
		if enabled && len(src.Systemd.Collect.Units) > 0 {
			units := make([]string, len(src.Systemd.Collect.Units))
			for i, u := range src.Systemd.Collect.Units {
				units[i] = string(u)
			}
			dst.Systemd.Units = units
		}
	}
	if enabled, set := nodeExporterCollectorEnabledFromPolicy(src.Softirqs.CollectionPolicy); set {
		dst.Softirqs.Enabled = enabled
	}
}

func (c *Config) mergeNodeExporterConfiguration(cmYAML string, nec configv1alpha1.NodeExporterConfig) {
	if configMapYAMLDeclaresNodeExporter(cmYAML) {
		return
	}
	if clusterMonitoringNodeExporterSpecEmpty(nec) {
		return
	}

	ne := &c.ClusterMonitoringConfiguration.NodeExporterConfig
	if nec.MaxProcs > 0 {
		ne.MaxProcs = uint32(nec.MaxProcs)
	}
	if nec.IgnoredNetworkDevices != nil {
		devs := make([]string, len(*nec.IgnoredNetworkDevices))
		for i, d := range *nec.IgnoredNetworkDevices {
			devs[i] = string(d)
		}
		ne.IgnoredNetworkDevices = &devs
	}
	if res := containerResourcesFromCRD(nec.Resources); res != nil {
		ne.Resources = res
	}
	mergeNodeExporterCollectorsFromCRD(&ne.Collectors, nec.Collectors)
}

// clusterMonitoringMetricsServerSpecEmpty reports whether the CR's
// metricsServer stanza contains no user-set field. The API uses a value type,
// so omitted in the manifest is always the zero struct here.
func clusterMonitoringMetricsServerSpecEmpty(msc configv1alpha1.MetricsServerConfig) bool {
	if msc.Verbosity != "" {
		return false
	}
	if len(msc.NodeSelector) > 0 {
		return false
	}
	if len(msc.Tolerations) > 0 {
		return false
	}
	if len(msc.Resources) > 0 {
		return false
	}
	if msc.Audit.Profile != "" {
		return false
	}
	if len(msc.TopologySpreadConstraints) > 0 {
		return false
	}
	return true
}

// clusterMonitoringPrometheusOperatorSpecEmpty reports whether the CR's
// prometheusOperatorConfig stanza contains no user-set field.
func clusterMonitoringPrometheusOperatorSpecEmpty(poc configv1alpha1.PrometheusOperatorConfig) bool {
	if poc.LogLevel != "" {
		return false
	}
	if len(poc.NodeSelector) > 0 {
		return false
	}
	if len(poc.Tolerations) > 0 {
		return false
	}
	if len(poc.Resources) > 0 {
		return false
	}
	if len(poc.TopologySpreadConstraints) > 0 {
		return false
	}
	return true
}

// clusterMonitoringAlertmanagerSpecEmpty reports whether the CR's
// alertmanagerConfig stanza contains no user intent.
func clusterMonitoringAlertmanagerSpecEmpty(ac configv1alpha1.AlertmanagerConfig) bool {
	return ac.DeploymentMode == ""
}

// clusterMonitoringMonitoringPluginSpecEmpty reports whether the CR's
// monitoringPluginConfig stanza contains no user-set field.
func clusterMonitoringMonitoringPluginSpecEmpty(mpc configv1alpha1.MonitoringPluginConfig) bool {
	if len(mpc.NodeSelector) > 0 {
		return false
	}
	if len(mpc.Tolerations) > 0 {
		return false
	}
	if len(mpc.Resources) > 0 {
		return false
	}
	if len(mpc.TopologySpreadConstraints) > 0 {
		return false
	}
	return true
}

func verbosityLevelToNumeric(level configv1alpha1.VerbosityLevel) uint8 {
	switch level {
	case configv1alpha1.VerbosityLevelErrors:
		return 0
	case configv1alpha1.VerbosityLevelInfo:
		return 2
	case configv1alpha1.VerbosityLevelTrace:
		return 3
	case configv1alpha1.VerbosityLevelTraceAll:
		return 4
	default:
		return 0
	}
}

func logLevelCRDToManifest(ll configv1alpha1.LogLevel) string {
	switch ll {
	case configv1alpha1.LogLevelError:
		return "error"
	case configv1alpha1.LogLevelWarn:
		return "warn"
	case configv1alpha1.LogLevelInfo:
		return "info"
	case configv1alpha1.LogLevelDebug:
		return "debug"
	default:
		return ""
	}
}

func containerResourcesFromCRD(resources []configv1alpha1.ContainerResource) *v1.ResourceRequirements {
	if len(resources) == 0 {
		return nil
	}
	out := &v1.ResourceRequirements{
		Requests: v1.ResourceList{},
		Limits:   v1.ResourceList{},
	}
	for _, res := range resources {
		if !res.Request.IsZero() {
			out.Requests[v1.ResourceName(res.Name)] = res.Request
		}
		if !res.Limit.IsZero() {
			out.Limits[v1.ResourceName(res.Name)] = res.Limit
		}
	}
	return out
}

func (c *Config) mergeMetricsServerConfiguration(msc configv1alpha1.MetricsServerConfig) {
	// Metrics Server (Phase 1): if the ConfigMap already has metricsServer, mergeMetricsServerConfiguration
	// is a no-op.
	if c.ClusterMonitoringConfiguration.MetricsServerConfig != nil {
		return
	}

	// Spec.MetricsServerConfig is a struct value—unset in YAML is a zero
	// struct in Go, not nil— so only merge when the CR author defined at least
	// one field.
	if clusterMonitoringMetricsServerSpecEmpty(msc) {
		return
	}

	cfg := &MetricsServerConfig{}

	if msc.Verbosity != "" {
		cfg.Verbosity = verbosityLevelToNumeric(msc.Verbosity)
	}
	cfg.NodeSelector = msc.NodeSelector
	cfg.Tolerations = msc.Tolerations
	if res := containerResourcesFromCRD(msc.Resources); res != nil {
		cfg.Resources = res
	}
	if msc.Audit.Profile != "" {
		cfg.Audit = &Audit{
			Profile: auditv1.Level(string(msc.Audit.Profile)),
		}
	}
	cfg.TopologySpreadConstraints = msc.TopologySpreadConstraints

	c.ClusterMonitoringConfiguration.MetricsServerConfig = cfg
}

func (c *Config) mergePrometheusOperatorConfiguration(poc configv1alpha1.PrometheusOperatorConfig) {
	if c.ClusterMonitoringConfiguration.PrometheusOperatorConfig != nil {
		return
	}
	if clusterMonitoringPrometheusOperatorSpecEmpty(poc) {
		return
	}

	cfg := &PrometheusOperatorConfig{}

	if poc.LogLevel != "" {
		cfg.LogLevel = logLevelCRDToManifest(poc.LogLevel)
	}
	cfg.NodeSelector = poc.NodeSelector
	cfg.Tolerations = poc.Tolerations
	cfg.Resources = containerResourcesFromCRD(poc.Resources)
	cfg.TopologySpreadConstraints = poc.TopologySpreadConstraints

	c.ClusterMonitoringConfiguration.PrometheusOperatorConfig = cfg
}

func (c *Config) mergeMonitoringPluginConfiguration(mpc configv1alpha1.MonitoringPluginConfig) {
	if c.ClusterMonitoringConfiguration.MonitoringPluginConfig != nil {
		return
	}
	if clusterMonitoringMonitoringPluginSpecEmpty(mpc) {
		return
	}

	cfg := &MonitoringPluginConfig{}
	cfg.NodeSelector = mpc.NodeSelector
	cfg.Tolerations = mpc.Tolerations
	cfg.Resources = containerResourcesFromCRD(mpc.Resources)
	cfg.TopologySpreadConstraints = mpc.TopologySpreadConstraints

	c.ClusterMonitoringConfiguration.MonitoringPluginConfig = cfg
}

func (c *Config) mergeAlertmanagerConfiguration(ac configv1alpha1.AlertmanagerConfig) {
	if c.ClusterMonitoringConfiguration.AlertmanagerMainConfig != nil {
		return
	}
	if clusterMonitoringAlertmanagerSpecEmpty(ac) {
		return
	}

	cfg := &AlertmanagerMainConfig{}
	switch ac.DeploymentMode {
	case configv1alpha1.AlertManagerDeployModeDisabled:
		cfg.Enabled = ptr.To(false)
	case configv1alpha1.AlertManagerDeployModeDefaultConfig:
		cfg.Enabled = ptr.To(true)
	case configv1alpha1.AlertManagerDeployModeCustomConfig:
		cfg.Enabled = ptr.To(true)
		mergeAlertmanagerCustomConfigFromCRD(cfg, ac.CustomConfig)
	default:
		return
	}
	c.ClusterMonitoringConfiguration.AlertmanagerMainConfig = cfg
}

func mergeAlertmanagerCustomConfigFromCRD(dst *AlertmanagerMainConfig, cc configv1alpha1.AlertmanagerCustomConfig) {
	if ll := logLevelCRDToManifest(cc.LogLevel); ll != "" {
		dst.LogLevel = ll
	}
	if len(cc.NodeSelector) > 0 {
		dst.NodeSelector = cc.NodeSelector
	}
	dst.Resources = containerResourcesFromCRD(cc.Resources)
	if len(cc.Secrets) > 0 {
		for _, s := range cc.Secrets {
			dst.Secrets = append(dst.Secrets, string(s))
		}
	}
	if len(cc.Tolerations) > 0 {
		dst.Tolerations = cc.Tolerations
	}
	if len(cc.TopologySpreadConstraints) > 0 {
		dst.TopologySpreadConstraints = cc.TopologySpreadConstraints
	}
	if cc.VolumeClaimTemplate != nil {
		dst.VolumeClaimTemplate = persistentVolumeClaimToEmbedded(cc.VolumeClaimTemplate)
	}
}

func persistentVolumeClaimToEmbedded(pvc *v1.PersistentVolumeClaim) *monv1.EmbeddedPersistentVolumeClaim {
	if pvc == nil {
		return nil
	}
	em := &monv1.EmbeddedPersistentVolumeClaim{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1.SchemeGroupVersion.String(),
			Kind:       "PersistentVolumeClaim",
		},
	}
	em.EmbeddedObjectMetadata.Name = pvc.Name
	em.EmbeddedObjectMetadata.Labels = pvc.Labels
	em.EmbeddedObjectMetadata.Annotations = pvc.Annotations
	em.Spec = pvc.Spec
	return em
}
