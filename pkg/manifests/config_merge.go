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
	"fmt"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"k8s.io/utils/ptr"
)

// mergeClusterMonitoringCRD merges the ClusterMonitoring CR spec into the ConfigMap-derived
// config when clusterMonitoring is non-nil. Phase 1 (pre-GA): for each top-level field, if the
// ConfigMap did not set it, use the CR; otherwise keep the ConfigMap and ignore the CR for that field.
func (c *Config) mergeClusterMonitoringCRD(clusterMonitoring *configv1alpha1.ClusterMonitoring) error {
	if clusterMonitoring == nil {
		return nil
	}

	// User workload: use the CR only if the ConfigMap did not set enableUserWorkload.
	if c.ClusterMonitoringConfiguration.UserWorkloadEnabled == nil && clusterMonitoring.Spec.UserDefined.Mode != "" {
		c.ClusterMonitoringConfiguration.UserWorkloadEnabled = ptr.To(clusterMonitoring.Spec.UserDefined.Mode == configv1alpha1.UserDefinedNamespaceIsolated)
	}

	if err := c.mergeMetricsServerConfiguration(clusterMonitoring.Spec.MetricsServerConfig); err != nil {
		return fmt.Errorf("metricsServerConfig: %w", err)
	}
	if err := c.mergePrometheusOperatorConfiguration(clusterMonitoring.Spec.PrometheusOperatorConfig); err != nil {
		return fmt.Errorf("prometheusOperatorConfig: %w", err)
	}
	c.mergePrometheusOperatorAdmissionWebhookConfiguration(clusterMonitoring.Spec.PrometheusOperatorAdmissionWebhookConfig)
	if err := c.mergeAlertmanagerConfiguration(clusterMonitoring.Spec.AlertmanagerConfig); err != nil {
		return fmt.Errorf("alertmanagerConfig: %w", err)
	}
	c.mergeMonitoringPluginConfiguration(clusterMonitoring.Spec.MonitoringPluginConfig)
	c.mergeTelemeterClientConfiguration(clusterMonitoring.Spec.TelemeterClientConfig)
	c.mergeThanosQuerierConfiguration(clusterMonitoring.Spec.ThanosQuerierConfig)
	c.mergeOpenShiftStateMetricsConfiguration(clusterMonitoring.Spec.OpenShiftStateMetricsConfig)
	if err := c.mergePrometheusK8sConfiguration(clusterMonitoring.Spec.PrometheusConfig); err != nil {
		return fmt.Errorf("prometheusConfig: %w", err)
	}

	if err := c.mergeKubeStateMetricsConfiguration(clusterMonitoring.Spec.KubeStateMetricsConfig); err != nil {
		return err
	}

	c.mergeNodeExporterConfiguration(clusterMonitoring.Spec.NodeExporterConfig)
	return nil
}

func clusterMonitoringNodeExporterCollectorsEmpty(col configv1alpha1.NodeExporterCollectorConfig) bool {
	for _, pol := range []configv1alpha1.NodeExporterCollectorCollectionPolicy{
		col.CpuFreq.CollectionPolicy,
		col.TcpStat.CollectionPolicy,
		col.Ethtool.CollectionPolicy,
		col.NetDev.CollectionPolicy,
		col.NetClass.CollectionPolicy,
		col.BuddyInfo.CollectionPolicy,
		col.MountStats.CollectionPolicy,
		col.Ksmd.CollectionPolicy,
		col.Processes.CollectionPolicy,
		col.Systemd.CollectionPolicy,
		col.Softirqs.CollectionPolicy,
	} {
		if pol != "" {
			return false
		}
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
		dst.NetDev.Enabled = ptr.To(enabled)
	}
	if enabled, set := nodeExporterCollectorEnabledFromPolicy(src.NetClass.CollectionPolicy); set {
		dst.NetClass.Enabled = ptr.To(enabled)
		if enabled && src.NetClass.Collect.StatsGatherer != "" {
			dst.NetClass.UseNetlink = ptr.To(src.NetClass.Collect.StatsGatherer == configv1alpha1.NodeExporterNetclassStatsGathererNetlink)
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

func (c *Config) mergeNodeExporterConfiguration(nec configv1alpha1.NodeExporterConfig) {
	if c.ClusterMonitoringConfiguration.NodeExporterConfig != nil {
		return
	}
	if clusterMonitoringNodeExporterSpecEmpty(nec) {
		return
	}

	ne := defaultNodeExporterConfig()
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
	c.ClusterMonitoringConfiguration.NodeExporterConfig = ne
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

// clusterMonitoringPrometheusOperatorAdmissionWebhookSpecEmpty reports whether the CR's
// prometheusOperatorAdmissionWebhookConfig stanza contains no user-set field.
func clusterMonitoringPrometheusOperatorAdmissionWebhookSpecEmpty(pawc configv1alpha1.PrometheusOperatorAdmissionWebhookConfig) bool {
	if len(pawc.Resources) > 0 {
		return false
	}
	if len(pawc.TopologySpreadConstraints) > 0 {
		return false
	}
	return true
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

// clusterMonitoringTelemeterClientSpecEmpty reports whether the CR's
// telemeterClientConfig stanza contains no user-set field.
func clusterMonitoringTelemeterClientSpecEmpty(tcc configv1alpha1.TelemeterClientConfig) bool {
	if len(tcc.NodeSelector) > 0 {
		return false
	}
	if len(tcc.Tolerations) > 0 {
		return false
	}
	if len(tcc.Resources) > 0 {
		return false
	}
	if len(tcc.TopologySpreadConstraints) > 0 {
		return false
	}
	return true
}

// clusterMonitoringThanosQuerierSpecEmpty reports whether the CR's
// thanosQuerierConfig stanza contains no user-set field.
func clusterMonitoringThanosQuerierSpecEmpty(tqc configv1alpha1.ThanosQuerierConfig) bool {
	if len(tqc.NodeSelector) > 0 {
		return false
	}
	if len(tqc.Tolerations) > 0 {
		return false
	}
	if len(tqc.Resources) > 0 {
		return false
	}
	if len(tqc.TopologySpreadConstraints) > 0 {
		return false
	}
	return true
}

// clusterMonitoringOpenShiftStateMetricsSpecEmpty reports whether the CR's
// openShiftStateMetricsConfig stanza contains no user-set field.
func clusterMonitoringOpenShiftStateMetricsSpecEmpty(osmc configv1alpha1.OpenShiftStateMetricsConfig) bool {
	if len(osmc.NodeSelector) > 0 {
		return false
	}
	if len(osmc.Tolerations) > 0 {
		return false
	}
	if len(osmc.Resources) > 0 {
		return false
	}
	if len(osmc.TopologySpreadConstraints) > 0 {
		return false
	}
	return true
}

// clusterMonitoringKubeStateMetricsSpecEmpty reports whether the CR's
// kubeStateMetricsConfig stanza contains no user-set field.
func clusterMonitoringKubeStateMetricsSpecEmpty(ksmc configv1alpha1.KubeStateMetricsConfig) bool {
	if len(ksmc.NodeSelector) > 0 {
		return false
	}
	if len(ksmc.Tolerations) > 0 {
		return false
	}
	if len(ksmc.Resources) > 0 {
		return false
	}
	if len(ksmc.TopologySpreadConstraints) > 0 {
		return false
	}
	if len(ksmc.AdditionalResourceLabels) > 0 {
		return false
	}
	return true
}

func verbosityLevelToNumeric(level configv1alpha1.VerbosityLevel) (uint8, error) {
	switch level {
	case configv1alpha1.VerbosityLevelErrors:
		return 0, nil
	case configv1alpha1.VerbosityLevelInfo:
		return 2, nil
	case configv1alpha1.VerbosityLevelTrace:
		return 3, nil
	case configv1alpha1.VerbosityLevelTraceAll:
		return 4, nil
	default:
		return 0, fmt.Errorf("unsupported verbosity level %q", level)
	}
}

func auditProfileCRDToManifest(profile configv1alpha1.AuditProfile) (auditv1.Level, error) {
	switch profile {
	case "":
		return "", nil
	case configv1alpha1.AuditProfileNone:
		return auditv1.LevelNone, nil
	case configv1alpha1.AuditProfileMetadata:
		return auditv1.LevelMetadata, nil
	case configv1alpha1.AuditProfileRequest:
		return auditv1.LevelRequest, nil
	case configv1alpha1.AuditProfileRequestResponse:
		return auditv1.LevelRequestResponse, nil
	default:
		return "", fmt.Errorf("unsupported audit profile %q", profile)
	}
}

func logLevelCRDToManifest(ll configv1alpha1.LogLevel) (string, error) {
	switch ll {
	case "":
		return "", nil
	case configv1alpha1.LogLevelError:
		return "error", nil
	case configv1alpha1.LogLevelWarn:
		return "warn", nil
	case configv1alpha1.LogLevelInfo:
		return "info", nil
	case configv1alpha1.LogLevelDebug:
		return "debug", nil
	default:
		return "", fmt.Errorf("unsupported log level %q", ll)
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

func (c *Config) mergeMetricsServerConfiguration(msc configv1alpha1.MetricsServerConfig) error {
	// Metrics Server (Phase 1): if the ConfigMap already has metricsServer, mergeMetricsServerConfiguration
	// is a no-op.
	if c.ClusterMonitoringConfiguration.MetricsServerConfig != nil {
		return nil
	}

	// Spec.MetricsServerConfig is a struct value—unset in YAML is a zero
	// struct in Go, not nil— so only merge when the CR author defined at least
	// one field.
	if clusterMonitoringMetricsServerSpecEmpty(msc) {
		return nil
	}

	cfg := &MetricsServerConfig{}

	if msc.Verbosity != "" {
		verbosity, err := verbosityLevelToNumeric(msc.Verbosity)
		if err != nil {
			return fmt.Errorf("verbosity: %w", err)
		}
		cfg.Verbosity = verbosity
	}
	cfg.NodeSelector = msc.NodeSelector
	cfg.Tolerations = msc.Tolerations
	if res := containerResourcesFromCRD(msc.Resources); res != nil {
		cfg.Resources = res
	}
	if msc.Audit.Profile != "" {
		profile, err := auditProfileCRDToManifest(msc.Audit.Profile)
		if err != nil {
			return fmt.Errorf("audit.profile: %w", err)
		}
		cfg.Audit = &Audit{
			Profile: profile,
		}
	}
	cfg.TopologySpreadConstraints = msc.TopologySpreadConstraints

	c.ClusterMonitoringConfiguration.MetricsServerConfig = cfg
	return nil
}

func (c *Config) mergePrometheusOperatorConfiguration(poc configv1alpha1.PrometheusOperatorConfig) error {
	if c.ClusterMonitoringConfiguration.PrometheusOperatorConfig != nil {
		return nil
	}
	if clusterMonitoringPrometheusOperatorSpecEmpty(poc) {
		return nil
	}

	cfg := &PrometheusOperatorConfig{}

	if poc.LogLevel != "" {
		ll, err := logLevelCRDToManifest(poc.LogLevel)
		if err != nil {
			return fmt.Errorf("logLevel: %w", err)
		}
		cfg.LogLevel = ll
	}
	cfg.NodeSelector = poc.NodeSelector
	cfg.Tolerations = poc.Tolerations
	cfg.Resources = containerResourcesFromCRD(poc.Resources)
	cfg.TopologySpreadConstraints = poc.TopologySpreadConstraints

	c.ClusterMonitoringConfiguration.PrometheusOperatorConfig = cfg
	return nil
}

func (c *Config) mergePrometheusOperatorAdmissionWebhookConfiguration(pawc configv1alpha1.PrometheusOperatorAdmissionWebhookConfig) {
	if c.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig != nil {
		return
	}
	if clusterMonitoringPrometheusOperatorAdmissionWebhookSpecEmpty(pawc) {
		return
	}

	cfg := &PrometheusOperatorAdmissionWebhookConfig{}
	if res := containerResourcesFromCRD(pawc.Resources); res != nil {
		cfg.Resources = res
	}
	cfg.TopologySpreadConstraints = pawc.TopologySpreadConstraints

	c.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig = cfg
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

func (c *Config) mergeTelemeterClientConfiguration(tcc configv1alpha1.TelemeterClientConfig) {
	if c.ClusterMonitoringConfiguration.TelemeterClientConfig != nil {
		return
	}
	if clusterMonitoringTelemeterClientSpecEmpty(tcc) {
		return
	}

	cfg := &TelemeterClientConfig{}
	cfg.NodeSelector = tcc.NodeSelector
	cfg.Tolerations = tcc.Tolerations
	if res := containerResourcesFromCRD(tcc.Resources); res != nil {
		cfg.Resources = res
	}
	cfg.TopologySpreadConstraints = tcc.TopologySpreadConstraints

	c.ClusterMonitoringConfiguration.TelemeterClientConfig = cfg
}

func (c *Config) mergeThanosQuerierConfiguration(tqc configv1alpha1.ThanosQuerierConfig) {
	if c.ClusterMonitoringConfiguration.ThanosQuerierConfig != nil {
		return
	}
	if clusterMonitoringThanosQuerierSpecEmpty(tqc) {
		return
	}

	cfg := &ThanosQuerierConfig{}
	cfg.NodeSelector = tqc.NodeSelector
	cfg.Tolerations = tqc.Tolerations
	if res := containerResourcesFromCRD(tqc.Resources); res != nil {
		cfg.Resources = res
	}
	cfg.TopologySpreadConstraints = tqc.TopologySpreadConstraints

	c.ClusterMonitoringConfiguration.ThanosQuerierConfig = cfg
}

func (c *Config) mergeOpenShiftStateMetricsConfiguration(osmc configv1alpha1.OpenShiftStateMetricsConfig) {
	if c.ClusterMonitoringConfiguration.OpenShiftMetricsConfig != nil {
		return
	}
	if clusterMonitoringOpenShiftStateMetricsSpecEmpty(osmc) {
		return
	}

	cfg := &OpenShiftStateMetricsConfig{}
	cfg.NodeSelector = osmc.NodeSelector
	cfg.Tolerations = osmc.Tolerations
	cfg.Resources = containerResourcesFromCRD(osmc.Resources)
	cfg.TopologySpreadConstraints = osmc.TopologySpreadConstraints

	c.ClusterMonitoringConfiguration.OpenShiftMetricsConfig = cfg
}

// kubeStateMetricsResourceNameToInternal maps the CRD PascalCase resource
// names ("Job", "CronJob") to the lowercase plural form used by the internal
// KubeStateMetricsConfig / validateAdditionalResourceLabels ("jobs", "cronjobs").
var kubeStateMetricsResourceNameToInternal = map[configv1alpha1.KubeStateMetricsResourceName]string{
	configv1alpha1.KubeStateMetricsResourceJob:     "jobs",
	configv1alpha1.KubeStateMetricsResourceCronJob: "cronjobs",
}

func additionalResourceLabelsFromCRD(crdLabels []configv1alpha1.KubeStateMetricsResourceLabels) ([]ResourceLabels, error) {
	if len(crdLabels) == 0 {
		return nil, nil
	}
	out := make([]ResourceLabels, 0, len(crdLabels))
	for _, rl := range crdLabels {
		internalName, ok := kubeStateMetricsResourceNameToInternal[rl.Resource]
		if !ok {
			return nil, fmt.Errorf("unknown kube-state-metrics resource name %q", rl.Resource)
		}
		labels := make([]string, 0, len(rl.Labels))
		for _, l := range rl.Labels {
			labels = append(labels, string(l))
		}
		out = append(out, ResourceLabels{
			Resource: internalName,
			Labels:   labels,
		})
	}
	return out, nil
}

func (c *Config) mergeKubeStateMetricsConfiguration(ksmc configv1alpha1.KubeStateMetricsConfig) error {
	if c.ClusterMonitoringConfiguration.KubeStateMetricsConfig != nil {
		return nil
	}
	if clusterMonitoringKubeStateMetricsSpecEmpty(ksmc) {
		return nil
	}

	cfg := &KubeStateMetricsConfig{}
	cfg.NodeSelector = ksmc.NodeSelector
	cfg.Tolerations = ksmc.Tolerations
	cfg.Resources = containerResourcesFromCRD(ksmc.Resources)
	cfg.TopologySpreadConstraints = ksmc.TopologySpreadConstraints

	rl, err := additionalResourceLabelsFromCRD(ksmc.AdditionalResourceLabels)
	if err != nil {
		return fmt.Errorf("kubeStateMetrics.additionalResourceLabels: %w", err)
	}
	cfg.AdditionalResourceLabels = rl

	c.ClusterMonitoringConfiguration.KubeStateMetricsConfig = cfg
	return nil
}

func (c *Config) mergeAlertmanagerConfiguration(ac configv1alpha1.AlertmanagerConfig) error {
	if c.ClusterMonitoringConfiguration.AlertmanagerMainConfig != nil {
		return nil
	}
	if clusterMonitoringAlertmanagerSpecEmpty(ac) {
		return nil
	}

	cfg := &AlertmanagerMainConfig{}
	switch ac.DeploymentMode {
	case configv1alpha1.AlertManagerDeployModeDisabled:
		cfg.Enabled = ptr.To(false)
	case configv1alpha1.AlertManagerDeployModeDefaultConfig:
		cfg.Enabled = ptr.To(true)
	case configv1alpha1.AlertManagerDeployModeCustomConfig:
		cfg.Enabled = ptr.To(true)
		if err := mergeAlertmanagerCustomConfigFromCRD(cfg, ac.CustomConfig); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported alertmanager deployment mode %q", ac.DeploymentMode)
	}
	c.ClusterMonitoringConfiguration.AlertmanagerMainConfig = cfg
	return nil
}

func mergeAlertmanagerCustomConfigFromCRD(dst *AlertmanagerMainConfig, cc configv1alpha1.AlertmanagerCustomConfig) error {
	if cc.LogLevel != "" {
		ll, err := logLevelCRDToManifest(cc.LogLevel)
		if err != nil {
			return fmt.Errorf("logLevel: %w", err)
		}
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
	return nil
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
