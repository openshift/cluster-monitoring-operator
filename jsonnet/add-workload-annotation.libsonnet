{
  addWorkloadAnnotation(o): {
    local annotation = {
      'target.workload.openshift.io/management': '{"effect": "PreferredDuringScheduling"}',
    },
    local addAnnotation(o) = o {
      [if std.setMember(o.kind, ['DaemonSet', 'Deployment', 'ReplicaSet']) then 'spec']+: {
        template+: {
          metadata+: {
            annotations+: annotation,
          },
        },
      },
      [if std.setMember(o.kind, ['Alertmanager', 'Prometheus', 'ThanosRuler']) then 'spec']+:
        {
          podMetadata+: {
            annotations+: annotation,
          },
        },
    },
    [k]: addAnnotation(o[k])
    for k in std.objectFields(o)
  },
}
