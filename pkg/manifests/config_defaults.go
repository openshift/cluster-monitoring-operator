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

	"github.com/prometheus/common/model"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"k8s.io/utils/ptr"
)

func defaultClusterMonitoringConfiguration() ClusterMonitoringConfiguration {
	return ClusterMonitoringConfiguration{
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
}

func (c *Config) applyDefaults() {
	if c.Images == nil {
		c.Images = &Images{}
	}
	if c.ClusterMonitoringConfiguration == nil {
		c.ClusterMonitoringConfiguration = &ClusterMonitoringConfiguration{}
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
	if c.ClusterMonitoringConfiguration.AlertmanagerMainConfig == nil {
		c.ClusterMonitoringConfiguration.AlertmanagerMainConfig = &AlertmanagerMainConfig{}
	}

	// UserWorkloadEnabled is left nil when not set by ConfigMap so the operator can
	// apply ClusterMonitoring CRD merge (UserDefined mode) when the feature gate is on.
	// The operator defaults it to false after merge when still nil.

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

	// MetricsServerConfig is left nil when not set by ConfigMap so the operator can
	// apply ClusterMonitoring CRD merge (MetricsServerConfig from CR) when the feature gate is on.
	// EnsureSafeDefaults() is called after merge and fills MetricsServerConfig when still nil.

	if c.ClusterMonitoringConfiguration.MetricsServerConfig != nil {
		if c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit == nil {
			c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit = &Audit{}
		}
		if c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit.Profile == "" {
			c.ClusterMonitoringConfiguration.MetricsServerConfig.Audit.Profile = auditv1.LevelMetadata
		}
	}
	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile == "" {
		c.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile = FullCollectionProfile
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

func scrapeIntervalLimits() (model.Duration, model.Duration) {
	lowerLimit, _ := model.ParseDuration("5s")
	upperLimit, _ := model.ParseDuration("5m")
	return lowerLimit, upperLimit
}

func evaluationIntervalLimits() (model.Duration, model.Duration) {
	lowerLimit, _ := model.ParseDuration("5s")
	upperLimit, _ := model.ParseDuration("5m")
	return lowerLimit, upperLimit
}

func (u *UserWorkloadConfiguration) checkScrapeInterval() error {
	if u.Prometheus == nil || u.Prometheus.ScrapeInterval == "" {
		return nil
	}

	scrapeInterval, err := model.ParseDuration(u.Prometheus.ScrapeInterval)

	if err != nil {
		return fmt.Errorf("invalid scrape interval value: %w", err)
	}

	allowedLowerLimit, allowedUpperLimit := scrapeIntervalLimits()

	if (scrapeInterval < allowedLowerLimit) || (scrapeInterval > allowedUpperLimit) {
		return fmt.Errorf("Prometheus scrape interval value %q outside of the allowed range [%q, %q]", u.Prometheus.ScrapeInterval, allowedLowerLimit, allowedUpperLimit)
	}
	return nil
}

func (u *UserWorkloadConfiguration) checkPrometheusEvaluationInterval() error {
	if u.Prometheus == nil || u.Prometheus.EvaluationInterval == "" {
		return nil
	}

	evaluationInterval, err := model.ParseDuration(u.Prometheus.EvaluationInterval)

	if err != nil {
		return fmt.Errorf("invalid evaluation interval value: %w", err)
	}

	allowedLowerLimit, allowedUpperLimit := evaluationIntervalLimits()

	if (evaluationInterval < allowedLowerLimit) || (evaluationInterval > allowedUpperLimit) {
		return fmt.Errorf("Prometheus evaluation interval value %q outside of the allowed range [%q, %q]", u.Prometheus.EvaluationInterval, allowedLowerLimit, allowedUpperLimit)
	}
	return nil
}

func (u *UserWorkloadConfiguration) checkThanosRulerEvaluationInterval() error {
	if u.ThanosRuler == nil || u.ThanosRuler.EvaluationInterval == "" {
		return nil
	}

	evaluationInterval, err := model.ParseDuration(u.ThanosRuler.EvaluationInterval)

	if err != nil {
		return fmt.Errorf("invalid evaluation interval value: %w", err)
	}

	allowedLowerLimit, allowedUpperLimit := evaluationIntervalLimits()

	if (evaluationInterval < allowedLowerLimit) || (evaluationInterval > allowedUpperLimit) {
		return fmt.Errorf("Thanos Ruler evaluation interval value %q outside of the allowed range [%q, %q]", u.ThanosRuler.EvaluationInterval, allowedLowerLimit, allowedUpperLimit)
	}
	return nil
}

func (u *UserWorkloadConfiguration) check() error {
	if u == nil {
		return nil
	}

	if err := u.checkScrapeInterval(); err != nil {
		return err
	}

	if err := u.checkPrometheusEvaluationInterval(); err != nil {
		return err
	}

	if err := u.checkThanosRulerEvaluationInterval(); err != nil {
		return err
	}

	return nil
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
