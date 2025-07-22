// Parse the telemetry config to extract properly grouped matchers
local telemetryConfigYaml = std.parseYaml(importstr '../../manifests/0000_50_cluster-monitoring-operator_04-config.yaml');
local telemetryMatches = std.parseYaml(telemetryConfigYaml.data['metrics.yaml']).matches;

// Extract metric name from a telemetry match expression
local extractMetricName(expr) =
  local quoteMatch = std.findSubstr('"', expr);
  assert std.length(quoteMatch) >= 2;
  local name = expr[quoteMatch[0]+1:quoteMatch[1]];

  local nameMatch = std.findSubstr('__name__="', expr);
  local regexMatch = std.findSubstr('__name__=~"', expr);
  if std.length(regexMatch) > 0 then
    std.strReplace(name, '.*', 'wildcard')
  else
    name;

local maybeAddNameLabel(expr) =
  local regexMatch = std.findSubstr('__name__=~"', expr);
  # We need to keep track of the metric name in case the match contains a regex.
  # Otherwise Prometheus will log `execution: vector cannot contain metrics with the same labelset`
  # since the metric name is dropped while querying. See also https://github.com/prometheus/prometheus/issues/11397
  # We reset the correct label name in the remote_write config.
  if std.length(regexMatch) > 0 then
    'label_replace(%s,"name_label","$1","__name__", "(.+)")' % expr
  else
    expr;

// Generate individual recording rules for each properly grouped telemetry matcher
local generateTelemetryRules() = [
  {
    record: 'telemetry:' + extractMetricName(match),
    expr: maybeAddNameLabel(match),
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
