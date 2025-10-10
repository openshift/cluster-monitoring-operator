{
  local minimalLabel = {
    'monitoring.openshift.io/collection-profile': 'minimal',
  },
  local telemetryLabel = {
    'monitoring.openshift.io/collection-profile': 'telemetry',
  },
  // 1. Add the profile prefix to the ServiceMonitor name
  // 2. Add the profile label "monitoring.openshift.io/collection-profile: <profile>"
  // 3. Add a metricRelabelings with action keep and regex equal to metrics
  local run(sm, metrics, label) = sm {
    metadata+: {
      name+: '-' + label['monitoring.openshift.io/collection-profile'],
      labels+: label,
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

  minimal(sm, metrics): run(removeDrop(sm), metrics, minimalLabel),
  telemetry(sm, metrics): run(removeDrop(sm), metrics, telemetryLabel),
}
