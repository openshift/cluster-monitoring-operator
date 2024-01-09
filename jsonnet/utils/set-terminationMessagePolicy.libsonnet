{
  setTerminationMessagePolicy(o): o {
    local addTerminationMessagePolicy(o) = o {
      [if std.setMember(o.kind, ['DaemonSet', 'Deployment', 'ReplicaSet']) then 'spec']+: {
        template+: {
          spec+: {
            containers: [
              c {
                terminationMessagePolicy: 'FallbackToLogsOnError',
              }
              for c in super.containers
            ],
          },
        },
      },
      [if std.setMember(o.kind, ['Prometheus', 'Alertmanager', 'ThanosRuler']) then 'spec']+: {
        containers: [
          c {
            terminationMessagePolicy: 'FallbackToLogsOnError',
          }
          for c in super.containers
        ],
      },
    },
    [k]: addTerminationMessagePolicy(o[k])
    for k in std.objectFields(o)
  },
}
