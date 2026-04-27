// This file acts as the single source of truth for the telemetry whitelist as
// well as the associated monitors for the telemetry collection profile. Before
// adding a telemetry entry, please read the following notes:
// * Teams are advised to add entries for telemetry (as they did earlier in
// manifests/0000_50_cluster-monitoring-operator_04-config.yaml), here instead.
// * Each entry must have the following fields, the absence of which will cause
// generation to fail:
//   * metadata: The metadata associated with the rule. This consists of:
//     * owners: The entities that own this rule.
//     * description: A description of what this rule captures, and why.
//     * label_values: The set of bounded label values for all the selectors the
//     rule allows.
//     * consumers: The entities that rely on this rule for their mixin needs.
//   * rule: The Prometheus recording rule, with or without selectors.
//   * monitor_metrics: A mapping of monitor keys to arrays of metric names
//   that the monitor tracks. Please note that:
//      * all monitor names that this rule associates to for any of its metrics
//      should be defined in the map. These must be exhaustive and account for
//      all metrics used in the rule, and,
//      * all metric names used in the rule must be associated with at least one
//      monitor in this map. These must be exhaustive and account for all
//      metrics used in the rule.
// * After adding entries here, don't forget to run `make generate`.
//
// This will use the entries below to generate the whitelist, as well as the
// monitor-to-metrics maps to help generate telemetry monitors IF they are
// associated with in-cluster components.
//
// Monitors for components external to what's housed under this repository are
// not generated, but that information is still maintained.
local o = import './telemetry-allowlist-and-monitors-entries.libsonnet';
local entries = o.entries;
local cmoMonitors = o.cmoMonitors;

// Each entry in the whitelist will continue to adhere to the existing pattern,
// with the exception of marker comments, i.e.,
// #
// # owners: (`metadata.owners`)
// #
// # `metadata.description`
// # Expected labels:\n`metadata.label_values`
// #
// # consumers: (`metadata.consumers`)
// #
// # [markers]
// - `rule`
local generateTelemetryWhitelistFromEntries(entries) =
  local matches = std.join('\n', std.flatMap(
    function(entry)
      local rule = entry.rule;
      local metadata = entry.metadata;
      local owners = metadata.owners;
      local consumers = metadata.consumers;
      local description = metadata.description;
      local label_values = metadata.label_values;
      local monitor_metrics = entry.monitor_metrics;
      local monitor_keys = std.objectFields(monitor_metrics);
      []
      +  // owners and description
      [
        '#',
        '# owners: (%s)' % std.join(', ', owners),
        '#',
        '# ' + description,
      ]
      +  // labels
      (if std.length(std.objectFields(label_values)) == 0 then
         []
       else
         [
           '#',
           '# Expected labels:',
         ]
         +
         std.flatMap(
           function(key) std.map(function(v) '# - %s: %s' % [key, v], label_values[key]),
           std.objectFields(label_values)
         ))
      +  // source monitors and metrics information
      [
        '#',
        '# This rule sources metrics from the following monitors:',
      ]
      +
      std.flatMap(
        function(k)
          local metrics = monitor_metrics[k];
          if k == '' then
            std.map(
              function(m) '# - <unknown>: %s' % m,
              metrics
            )
          else
            ['# - %s: %s' % [k, std.join(', ', metrics)]],
        monitor_keys
      )
      +  // consumers
      (if std.length(consumers) > 0 then
         [
           '#',
           '# consumers: (%s)' % std.join(', ', consumers),
         ]
       else [])
      +  // marker comments to provide additional context
      (
        local marker = 'marker:';
        local cmoMonitorKeys = std.filter(function(k) std.objectHas(cmoMonitors, k), monitor_keys);
        local externalMonitorKeys = std.filter(function(k) k == '' || !std.objectHas(cmoMonitors, k), monitor_keys);
        local hasCMOMonitors = std.length(cmoMonitorKeys) > 0;
        local hasExternalMonitors = std.length(externalMonitorKeys) > 0;
        local ruleName =
          local matches = std.findSubstr('__name__="', rule);
          if std.length(matches) > 0 then
            local start = matches[0] + std.length('__name__="');
            local remaining = rule[start:];
            local endQuote = std.findSubstr('"', remaining);
            if std.length(endQuote) > 0 then
              remaining[:endQuote[0]]
            else
              null
          else
            null;
        local isMetricAsRule =
          std.length(monitor_keys) == 1 &&
          std.length(monitor_metrics[monitor_keys[0]]) == 1 &&
          ruleName != null &&
          monitor_metrics[monitor_keys[0]][0] == ruleName;
        ['#']
        +
        (if isMetricAsRule then
           ['#' + marker + 'isMetricAsRule']
         else
           [])
        +
        (if hasCMOMonitors && !hasExternalMonitors then
           ['#' + marker + 'reliesExclusivelyOnCMOmonitors']
         else if hasCMOMonitors && hasExternalMonitors then
           ['#' + marker + 'reliesPartiallyOnCMOmonitors']
         else if hasExternalMonitors then
           ['#' + marker + 'reliesExclusivelyOnExternalMonitors']
         else
           [])
      )
      +  // rule
      [
        '#',
        "- '%s'" % rule,
      ],
    entries
  ));
  {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      name: 'telemetry-config',
      namespace: 'openshift-monitoring',
      annotations: {
        'include.release.openshift.io/hypershift': 'true',
        'include.release.openshift.io/ibm-cloud-managed': 'true',
        'include.release.openshift.io/self-managed-high-availability': 'true',
        'include.release.openshift.io/single-node-developer': 'true',
      },
    },
    data: {
      'metrics.yaml': |||
        matches:
      ||| + matches,
    },
  };

// aggregateMonitorMetricsFromEntries takes all the entries and forms an
// aggregated map of monitor metrics to be used in monitor definitions.
local aggregateMonitorMetricsFromEntries(entries) =
  local aggregatorFn(aggregator, entry) =
    local monitor_metrics = entry.monitor_metrics;
    std.foldl(
      function(aggregatorCopy, monitorKey)
        if monitorKey != '' then
          aggregatorCopy {
            [monitorKey]:
              if std.objectHas(aggregatorCopy, monitorKey) then
                aggregatorCopy[monitorKey] + monitor_metrics[monitorKey]
              else
                monitor_metrics[monitorKey],
          }
        else
          aggregatorCopy,
      std.objectFields(monitor_metrics),
      aggregator
    );
  local aggregated = std.foldl(
    aggregatorFn,
    entries,
    {}
  );
  {
    [monitorKey]: std.set(aggregated[monitorKey])
    for monitorKey in std.objectFields(aggregated)
  };

{
  monitorKeysToMetricsMap: aggregateMonitorMetricsFromEntries(entries),
  whitelist: generateTelemetryWhitelistFromEntries(entries),
}
