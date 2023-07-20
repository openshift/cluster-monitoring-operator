package profiles

import (
	"fmt"

	metricsprofiles "github.com/openshift/cluster-monitoring-operator/hack/monitorgen/internal/metrics"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
)

var (
	// Map that contains ServiceMonitor names as keys and a list of metrics as
	// value
	minimalProfileMetrics = map[string][]string{
		"kubelet":            metricsprofiles.KubeletMinimal,
		"etcd":               metricsprofiles.EtcdMinimal,
		"node-exporter":      metricsprofiles.NodeExporterMinimal,
		"kube-state-metrics": metricsprofiles.KubeStateMetricsMinimal,
		"prometheus-adapter": metricsprofiles.PrometheusAdapterMinimal,
	}
)

func GenerateCollectionProfileMinimal(sm monitoringv1.ServiceMonitor, parentSMPath, minimalMetricsFilePath string) {
	generateProfile(sm, parentSMPath, minimalMetricsFilePath, manifests.MinimalCollectionProfile, minimalProfileMetrics, func(sm *monitoringv1.ServiceMonitor, metrics []string) {
		for i := 0; i < len(sm.Spec.Endpoints); i++ {
			endpoint := &sm.Spec.Endpoints[i]
			// Remove drop relabel configs
			if len(endpoint.MetricRelabelConfigs) > 0 {
				endpoint.MetricRelabelConfigs = removeDrop(endpoint.MetricRelabelConfigs)
			}
			// Add keep relabel configs
			endpoint.MetricRelabelConfigs = append(endpoint.MetricRelabelConfigs, keepMetrics(metrics))
		}
	})
}

// removeDrop goes through metricRelabelConfigs and
// returns a copy of metricRelabelConfigs without relabelConfigs that have the
// action "drop"
func removeDrop(metricRelabelConfigs []*monitoringv1.RelabelConfig) []*monitoringv1.RelabelConfig {
	mrc := make([]*monitoringv1.RelabelConfig, 1)
	for _, relabelConfig := range metricRelabelConfigs {
		if relabelConfig.Action == "drop" {
			continue
		}
		mrc = append(mrc, relabelConfig)
	}

	return mrc
}

// keepMetrics goes through the metrics in the slice metrics and joins
// in a string with "|", them returns a relabelConfig with action "keep" and the
// joined metrics in the regex field.
func keepMetrics(metrics []string) *monitoringv1.RelabelConfig {
	jointMetrics := metrics[0]
	for i := 1; i < len(metrics); i++ {
		jointMetrics = jointMetrics + "|" + metrics[i]
	}

	return &monitoringv1.RelabelConfig{
		Action: "keep",
		SourceLabels: []monitoringv1.LabelName{
			"__name__",
		},
		Regex: fmt.Sprintf("(%s)", jointMetrics),
	}
}
