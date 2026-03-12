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
	v1 "k8s.io/api/core/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"k8s.io/utils/ptr"
)

// MergeClusterMonitoringCRD merges the ClusterMonitoring CRD spec into the
// ConfigMap-derived config. Phase 1 merge rule: if a field is nil in the
// ConfigMap, use the CRD value; otherwise keep the ConfigMap value.
// Call EnsureSafeDefaults after this (or when CRD is not enabled) so the config is always safe.
func (c *Config) MergeClusterMonitoringCRD(clusterMonitoring *configv1alpha1.ClusterMonitoring) {
	if clusterMonitoring == nil {
		return
	}
	if c.ClusterMonitoringConfiguration == nil {
		c.ClusterMonitoringConfiguration = &ClusterMonitoringConfiguration{}
	}

	// UserDefined (CRD) -> UserWorkloadEnabled (ConfigMap): only set from CRD when ConfigMap has no opinion.
	if c.ClusterMonitoringConfiguration.UserWorkloadEnabled == nil && clusterMonitoring.Spec.UserDefined.Mode != "" {
		if v := applyUserDefinedMode(clusterMonitoring.Spec.UserDefined); v != nil {
			c.ClusterMonitoringConfiguration.UserWorkloadEnabled = v
		}
	}

	// MetricsServerConfig: merge from CRD so CRD values override ConfigMap when both are set.
	mergeMetricsServerConfigFromCRD(c, &clusterMonitoring.Spec.MetricsServerConfig)
}

// EnsureSafeDefaults sets safe defaults for fields that may be nil when
// neither ConfigMap nor CRD set them (e.g. when ClusterMonitoring CRD is not enabled).
// The operator should call this after MergeClusterMonitoringCRD (or when merge is skipped).
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

func mergeMetricsServerConfigFromCRD(c *Config, msc *configv1alpha1.MetricsServerConfig) {
	if c.ClusterMonitoringConfiguration.MetricsServerConfig == nil {
		c.ClusterMonitoringConfiguration.MetricsServerConfig = &MetricsServerConfig{}
	}
	cfg := c.ClusterMonitoringConfiguration.MetricsServerConfig

	if msc.Verbosity != "" {
		cfg.Verbosity = verbosityLevelToNumeric(msc.Verbosity)
	}
	if len(msc.NodeSelector) > 0 {
		cfg.NodeSelector = msc.NodeSelector
	}
	if len(msc.Tolerations) > 0 {
		cfg.Tolerations = msc.Tolerations
	}
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
		cfg.Audit.Profile = auditv1.Level(strings.ToLower(string(msc.Audit.Profile)))
	}
	if len(msc.TopologySpreadConstraints) > 0 {
		cfg.TopologySpreadConstraints = msc.TopologySpreadConstraints
	}
}
