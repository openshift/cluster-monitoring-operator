package metrics

import (
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

// ReconcileAttempts is a counter that indicates the number of attempts to reconcile the operator configuration.
var ReconcileAttempts = metrics.NewCounter(&metrics.CounterOpts{
	Name:           "cluster_monitoring_operator_reconcile_attempts_total",
	Help:           "Number of attempts to reconcile the operator configuration.",
	StabilityLevel: metrics.ALPHA,
})

// ReconcileStatus is a gauge that indicates the latest reconciliation state.
var ReconcileStatus = metrics.NewGauge(&metrics.GaugeOpts{
	Name:           "cluster_monitoring_operator_last_reconciliation_successful",
	Help:           "Latest reconciliation state. Set to 1 if last reconciliation succeeded, else 0.",
	StabilityLevel: metrics.ALPHA,
})

// CollectionProfile is a gauge vector that holds information about the collection profiles.
// All collection profiles, as stated in manifests.SupportedCollectionProfiles, are present as label values.
// Set to 1 for the configured collection profile, else 0.
var CollectionProfile = metrics.NewGaugeVec(&metrics.GaugeOpts{
	Name:           "cluster_monitoring_operator_collection_profile",
	Help:           "Information about collection profiles. Set to 1 for the configured collection profile, else 0.",
	StabilityLevel: metrics.ALPHA,
}, []string{"profile"})

var DeprecatedConfig = metrics.NewGaugeVec(&metrics.GaugeOpts{
	Name:           "cluster_monitoring_operator_deprecated_config_in_use",
	Help:           "Set to 1 for deprecated configuration fields that are still in use, else 0.",
	StabilityLevel: metrics.ALPHA,
}, []string{"configmap", "field", "deprecation_version"})

// Metrics for the webhook validation HTTP handler.
// They mimic the controller-runtime metrics which we can't use unfortunately
// because they are registered in another Prometheus registry and they are not
// exposed publicly.
var (
	// WebhookRequestLatency is a prometheus metric which is a histogram of the latency
	// of processing admission requests.
	// Buckets have been chosen to minimize the cardinality while providing
	// good-enough visibility.
	//
	// TODO(simonpasquier): add support for native histograms once it is
	// supported by k8s.io/component-base/metrics.
	WebhookRequestLatency = metrics.NewHistogramVec(
		&metrics.HistogramOpts{
			Name:    "cluster_monitoring_webhook_latency_seconds",
			Help:    "Histogram of the latency of processing admission requests",
			Buckets: []float64{0.1, 0.5, 1.0, 2.5, 5.0},
		},
		[]string{"webhook"},
	)

	// WebhookRequestTotal is a prometheus metric which is a counter of the total processed admission requests.
	WebhookRequestTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Name: "cluster_monitoring_webhook_requests_total",
			Help: "Total number of admission requests by HTTP status code.",
		},
		[]string{"webhook", "code"},
	)

	// WebhookRequestInFlight is a prometheus metric which is a gauge of the in-flight admission requests.
	WebhookRequestInFlight = metrics.NewGaugeVec(
		&metrics.GaugeOpts{
			Name: "cluster_monitoring_webhook_requests_in_flight",
			Help: "Current number of admission requests being served.",
		},
		[]string{"webhook"},
	)
)

func init() {
	// The API (metrics) server is instrumented to work with component-base.
	// Refer: https://github.com/kubernetes/kubernetes/blob/ec87834bae787ab6687921d65c3bcfde8a6e01b9/staging/src/k8s.io/apiserver/pkg/server/routes/metrics.go#L44.
	legacyregistry.MustRegister(ReconcileAttempts)
	legacyregistry.MustRegister(ReconcileStatus)
	legacyregistry.MustRegister(CollectionProfile)
	legacyregistry.MustRegister(DeprecatedConfig)
	legacyregistry.MustRegister(WebhookRequestTotal, WebhookRequestInFlight, WebhookRequestLatency)
}
