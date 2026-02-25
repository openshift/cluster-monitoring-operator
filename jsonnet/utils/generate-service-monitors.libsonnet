{
  local profiles = ['minimal', 'telemetry'],
  // 1. Check if we need to remove any existing "drop" metricRelabelings based on `shouldRemoveDrop`.
  // 2. Ensure no profile suffix is present in the ServiceMonitor name (this
  // happens when basing one monitor on another, for e.g., minimal and
  // telemetry, as the former derives telemetry metrics from the latter)
  // 3. Add the profile prefix to the ServiceMonitor name
  // 4. Add the profile label "monitoring.openshift.io/collection-profile: <profile>"
  // 5. If `metrics` is non-null, add a metricRelabelings with action keep and regex equal to metrics
  local run(smWithDrop, metrics, profile, shouldRemoveDrop) =
    local sm = if shouldRemoveDrop then removeDrop(smWithDrop) else smWithDrop;
    local currentName = sm.metadata.name;
    local baseName = std.foldl(
      function(name, p)
        local suffix = '-' + p;
        if std.endsWith(name, suffix) then
          std.substr(name, 0, std.length(name) - std.length(suffix))
        else
          name,
      profiles,
      currentName
    );
    sm {
      metadata+: {
        name: baseName + '-' + profile,
        labels+: {
          'monitoring.openshift.io/collection-profile': profile,
        },
      },
      spec+: {
        endpoints: std.map(
          function(e)
            if metrics != null then
              e {
                metricRelabelings+: [
                  {
                    sourceLabels: ['__name__'],
                    action: 'keep',
                    regex: '(' + metrics + ')',
                  },
                ],
              }
            else
              e,
          sm.spec.endpoints
        ),
      },
    },
  // Removes all metricRelabeling's with the action "drop" from
  // ServiceMonitor.spec.endpoint.metricRelabelings
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

  minimal(sm, metrics, removeDrop=true): run(sm, metrics, profiles[0], removeDrop),
  telemetry(sm, metrics, removeDrop=true): run(sm, metrics, profiles[1], removeDrop),
}
