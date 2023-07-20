package profiles

import (
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

type MinimalProfileGenerator struct {
	parentSMPath, minimalMetricsFilePath string
}

func (mpg MinimalProfileGenerator) PatchServiceMonitor(sm *monitoringv1.ServiceMonitor, metrics []string) {
	for i := 0; i < len(sm.Spec.Endpoints); i++ {
		endpoint := &sm.Spec.Endpoints[i]
		// Remove drop relabel configs
		if len(endpoint.MetricRelabelConfigs) > 0 {
			endpoint.MetricRelabelConfigs = removeDrop(endpoint.MetricRelabelConfigs)
		}
		// Add keep relabel configs
		endpoint.MetricRelabelConfigs = append(endpoint.MetricRelabelConfigs, keepMetrics(metrics))
	}
}

func (mpg MinimalProfileGenerator) Profile() manifests.CollectionProfile {
	return manifests.MinimalCollectionProfile
}

func (mpg MinimalProfileGenerator) DefaultMetrics() map[string][]string {
	return minimalProfileMetrics
}

func (mpg MinimalProfileGenerator) ParentSMPath() string {
	return mpg.parentSMPath
}

func (mpg MinimalProfileGenerator) MetricsFilePath() string {
	return mpg.minimalMetricsFilePath
}

func GenerateCollectionProfileMinimal(sm monitoringv1.ServiceMonitor, parentSMPath, minimalMetricsFilePath string) {
	generateProfile(&MinimalProfileGenerator{
		parentSMPath:           parentSMPath,
		minimalMetricsFilePath: minimalMetricsFilePath,
	}, sm)
}
