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
	v1 "k8s.io/api/core/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"k8s.io/utils/ptr"
)

// MergeClusterMonitoringCRD merges the ClusterMonitoring CR spec into the ConfigMap-derived
// config when clusterMonitoring is non-nil. Phase 1 (pre-GA): for each top-level field, if the
// ConfigMap did not set it, use the CR; otherwise keep the ConfigMap and ignore the CR for that field.
//
// The operator should always call this with nil when the feature gate is off or the CR is missing.
// EnsureSafeDefaults runs at the end here so callers do not need to invoke it separately.
func (c *Config) MergeClusterMonitoringCRD(clusterMonitoring *configv1alpha1.ClusterMonitoring) {
	if clusterMonitoring != nil {
		if c.ClusterMonitoringConfiguration == nil {
			c.ClusterMonitoringConfiguration = &ClusterMonitoringConfiguration{}
		}

		// User workload: use the CR only if the ConfigMap did not set enableUserWorkload.
		if c.ClusterMonitoringConfiguration.UserWorkloadEnabled == nil && clusterMonitoring.Spec.UserDefined.Mode != "" {
			if v := applyUserDefinedMode(clusterMonitoring.Spec.UserDefined); v != nil {
				c.ClusterMonitoringConfiguration.UserWorkloadEnabled = v
			}
		}

		// Metrics Server (Phase 1): if the ConfigMap already has metricsServer, mergeMetricsServerConfiguration
		// is a no-op. Spec.MetricsServerConfig is a struct value—unset in YAML is a zero struct in Go, not nil—
		// so only merge when the CR author set at least one field (avoids allocating an empty MetricsServerConfig).
		if clusterMonitoringMetricsServerSpecNonEmpty(clusterMonitoring.Spec.MetricsServerConfig) {
			c.mergeMetricsServerConfiguration(clusterMonitoring.Spec.MetricsServerConfig)
		}
	}
	c.EnsureSafeDefaults()
}

// EnsureSafeDefaults sets safe defaults for fields that may be nil when neither ConfigMap nor CR
// set them. MergeClusterMonitoringCRD invokes this at the end; direct use is for tests or special cases.
func (c *Config) EnsureSafeDefaults() {
	if c.ClusterMonitoringConfiguration == nil {
		return
	}
	if c.ClusterMonitoringConfiguration.UserWorkloadEnabled == nil {
		c.ClusterMonitoringConfiguration.UserWorkloadEnabled = ptr.To(false)
	}
	if c.ClusterMonitoringConfiguration.MetricsServerConfig == nil {
		c.ClusterMonitoringConfiguration.MetricsServerConfig = &MetricsServerConfig{
			Audit: &Audit{Profile: auditv1.LevelMetadata},
		}
	} else if c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit == nil {
		c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit = &Audit{Profile: auditv1.LevelMetadata}
	} else if c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit.Profile == "" {
		c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit.Profile = auditv1.LevelMetadata
	}
}

func applyUserDefinedMode(udm configv1alpha1.UserDefinedMonitoring) *bool {
	switch udm.Mode {
	case configv1alpha1.UserDefinedDisabled:
		return ptr.To(false)
	case configv1alpha1.UserDefinedNamespaceIsolated:
		return ptr.To(true)
	default:
		return nil
	}
}

// clusterMonitoringMetricsServerSpecNonEmpty reports whether the CR's metricsServer stanza contains any
// user-set field. The API uses a value type, so omitted in the manifest is always the zero struct here.
func clusterMonitoringMetricsServerSpecNonEmpty(msc configv1alpha1.MetricsServerConfig) bool {
	if msc.Verbosity != "" {
		return true
	}
	if len(msc.NodeSelector) > 0 {
		return true
	}
	if len(msc.Tolerations) > 0 {
		return true
	}
	if len(msc.Resources) > 0 {
		return true
	}
	if msc.Audit.Profile != "" {
		return true
	}
	if len(msc.TopologySpreadConstraints) > 0 {
		return true
	}
	return false
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

func (c *Config) mergeMetricsServerConfiguration(msc configv1alpha1.MetricsServerConfig) {
	if c.ClusterMonitoringConfiguration.MetricsServerConfig != nil {
		return
	}
	c.ClusterMonitoringConfiguration.MetricsServerConfig = &MetricsServerConfig{}
	cfg := c.ClusterMonitoringConfiguration.MetricsServerConfig

	if msc.Verbosity != "" {
		cfg.Verbosity = verbosityLevelToNumeric(msc.Verbosity)
	}
	cfg.NodeSelector = msc.NodeSelector
	cfg.Tolerations = msc.Tolerations
	if len(msc.Resources) > 0 {
		resources := &v1.ResourceRequirements{
			Requests: v1.ResourceList{},
			Limits:   v1.ResourceList{},
		}
		for _, res := range msc.Resources {
			if !res.Request.IsZero() {
				resources.Requests[v1.ResourceName(res.Name)] = res.Request
			}
			if !res.Limit.IsZero() {
				resources.Limits[v1.ResourceName(res.Name)] = res.Limit
			}
		}
		cfg.Resources = resources
	}
	if msc.Audit.Profile != "" {
		if cfg.Audit == nil {
			cfg.Audit = &Audit{}
		}
		cfg.Audit.Profile = auditv1.Level(string(msc.Audit.Profile))
	}
	cfg.TopologySpreadConstraints = msc.TopologySpreadConstraints
}
