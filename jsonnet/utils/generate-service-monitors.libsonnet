{
  local profiles = ['minimal', 'telemetry'],

  // Removes all metricRelabelings with the action "drop" from ServiceMonitor.spec.endpoint.metricRelabelings
  local removeDrop(sm) = sm {
    spec+: {
      endpoints: std.map(
        function(e) e +
                    if std.objectHas(e, 'metricRelabelings') then
                      {
                        metricRelabelings: [x for x in e.metricRelabelings if std.objectHas(x, 'action') && x.action != 'drop'],
                      } else {},
        sm.spec.endpoints
      ),
    },
  },

  // Ensure no profile suffix is present in the ServiceMonitor name.
  // This happens when basing one monitor on another, for e.g., minimal and full, as the former relies on the latter for its definition.
  local stripProfileSuffix(name) = std.foldl(
    function(n, p)
      local suffix = '-' + p;
      if std.endsWith(n, suffix) then
        std.substr(n, 0, std.length(n) - std.length(suffix))
      else
        n,
    profiles,
    name
  ),

  // Add the profile to the ServiceMonitor name and labels
  local addProfile(sm, profile) =
    local currentName = sm.metadata.name;
    local baseName = stripProfileSuffix(currentName);
    sm {
      metadata+: {
        name: baseName + '-' + profile,
        labels+: {
          'monitoring.openshift.io/collection-profile': profile,
        },
      },
    },

  // Returns a copy of the input service monitor with the provided list of metrics.
  // The metrics parameter is an array of metric names (e.g., ["metric1", "metric2", "metric3"]).
  // This function removes existing "drop" metricRelabelings before adding the keep filter,
  // since they become redundant when using a keep-only strategy (the keep action will
  // already filter out everything except the specified metrics).
  keepOnlyMetrics(sm, metrics):
    local smWithoutDrops = removeDrop(sm);
    local metricsRegex = std.join('|', metrics);
    smWithoutDrops {
      spec+: {
        endpoints: std.map(
          function(e)
            e {
              metricRelabelings+: [
                {
                  sourceLabels: ['__name__'],
                  action: 'keep',
                  regex: '(' + metricsRegex + ')',
                },
              ],
            },
          smWithoutDrops.spec.endpoints
        ),
      },
    },

  serviceMonitorForMinimalProfile(sm): addProfile(sm, profiles[0]),
  serviceMonitorForTelemetryProfile(sm): addProfile(sm, profiles[1]),
}
