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
func (c *Config) mergeClusterMonitoringCRD(clusterMonitoring *configv1alpha1.ClusterMonitoring) {
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
	cfg.Resources = containerResourcesFromCRD(msc.Resources)
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
		// Deploy with platform defaults (Enabled is nil → true via IsEnabled).
	case configv1alpha1.AlertManagerDeployModeCustomConfig:
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
