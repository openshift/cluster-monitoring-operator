{
  local minimalLabel = {
    'monitoring.openshift.io/collection-profile': 'minimal',
  },
  // 1. Add the prefix minimal to the ServiceMonitor name
  // 2. Add the minimal label "monitoring.openshift.io/collection-profile: minimal"
  // 3. Add a metricRelabelings with action keep and regex equal to metrics
  local minimal(sm, metrics) = sm {
    metadata+: {
      name+: '-minimal',
      labels+: minimalLabel,
    },
    spec+: {
      endpoints: std.map(
        function(e) e {
          metricRelabelings+: [
            {
              sourceLabels: ['__name__'],
              action: 'keep',
              regex: '(' + metrics + ')',
            },
          ],
        }, sm.spec.endpoints
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

  minimal(sm, metrics): minimal(removeDrop(sm), metrics),
}
