package framework

import (
	"encoding/json"

	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	dto "github.com/prometheus/client_model/go"
)

// MetricFamilies creates an array of Prometheus MetricFamily from the API
// metadata and series.
func MetricFamilies(rawMetadata, rawSeries []byte) ([]*dto.MetricFamily, error) {
	var j map[string]json.RawMessage
	err := json.Unmarshal(rawMetadata, &j)
	if err != nil {
		return nil, err
	}

	var metadatas map[string][]struct {
		Help string        `json:"help,omitempty"`
		Type v1.MetricType `json:"type,omitempty"`
	}
	err = json.Unmarshal(j["data"], &metadatas)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(rawSeries, &j)
	if err != nil {
		return nil, err
	}

	var series []map[string]string
	err = json.Unmarshal(j["data"], &series)
	if err != nil {
		return nil, err
	}

	var metricFamilies []*dto.MetricFamily
	for _, serie := range series {
		name := serie["__name__"]
		if _, ok := metadatas[name]; ok {
			metadata := metadatas[name][0]
			metricType := convertToDTOMetricType(metadata.Type)
			metricFamilies = append(metricFamilies, &dto.MetricFamily{
				Name:   &name,
				Help:   &metadata.Help,
				Type:   &metricType,
				Metric: []*dto.Metric{newMetric(metricType, serie)},
			})
		}
	}

	return metricFamilies, nil
}

func newMetric(metricType dto.MetricType, labels map[string]string) *dto.Metric {
	metric := &dto.Metric{}

	for n, v := range labels {
		name := n
		value := v
		metric.Label = append(metric.Label, &dto.LabelPair{
			Name:  &name,
			Value: &value,
		})
	}

	switch metricType {
	case dto.MetricType_COUNTER:
		metric.Counter = &dto.Counter{}
	case dto.MetricType_GAUGE:
		metric.Gauge = &dto.Gauge{}
	case dto.MetricType_HISTOGRAM:
		metric.Histogram = &dto.Histogram{}
	case dto.MetricType_SUMMARY:
		metric.Summary = &dto.Summary{}
	default:
		metric.Untyped = &dto.Untyped{}
	}

	return metric
}

func convertToDTOMetricType(metricType v1.MetricType) dto.MetricType {
	switch metricType {
	case v1.MetricTypeCounter:
		return dto.MetricType_COUNTER
	case v1.MetricTypeGauge:
		return dto.MetricType_GAUGE
	case v1.MetricTypeHistogram:
		return dto.MetricType_HISTOGRAM
	case v1.MetricTypeSummary:
		return dto.MetricType_SUMMARY
	default:
		return dto.MetricType_UNTYPED
	}
}
