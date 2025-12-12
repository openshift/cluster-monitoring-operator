// Parse the telemetry config to extract properly grouped matchers
local telemetryConfigYaml = std.parseYaml(importstr '../../manifests/0000_50_cluster-monitoring-operator_04-config.yaml');
local telemetryMatches = std.parseYaml(telemetryConfigYaml.data['metrics.yaml']).matches;

// Generate individual recording rules for each properly grouped telemetry matcher
local generateTelemetryRules() = [
  {
    record: 'telemetry:metric',
    # We keep track of the metric name in a label. For regex matchers this is
    # required, so we might as well do it consistently.
    # Otherwise Prometheus can log `execution: vector cannot contain metrics with the same labelset`
    # since the metric name is dropped while querying. See also https://github.com/prometheus/prometheus/issues/11397
    # We reset the correct label name in the remote_write config.
    expr: 'label_replace(%s,"__original_name_label__","$1","__name__", "(.+)")' % match
  }
  for match in telemetryMatches
];

function(params) {
  local cfg = params,
  local telemetryRules = generateTelemetryRules(),

  prometheusRule: {
    apiVersion: 'monitoring.coreos.com/v1',
    kind: 'PrometheusRule',
    metadata: {
      labels: cfg.commonLabels + {
        'role': 'telemetry-rules',
      },
      name: 'telemetry-recording-rules',
      namespace: cfg.namespace,
    },
    spec: {
      groups: [{
        name: 'telemetry-recording.rules',
        interval: '4m30s',
        rules: telemetryRules,
      }],
    },
  },
}
