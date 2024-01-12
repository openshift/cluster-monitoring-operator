{
  setTerminationMessagePolicy(o): o {
    local addTerminationMessagePolicy(o) = o {
      [if std.setMember(o.kind, std.set(['DaemonSet', 'Deployment'])) then 'spec']+: {
        template+: {
          spec+: {
            containers: [
              c {
                terminationMessagePolicy: 'FallbackToLogsOnError',
              }
              for c in o.spec.template.spec.containers
            ],
            [if 'initContainers' in o.spec.template.spec then 'initContainers']: [
              c {
                terminationMessagePolicy: 'FallbackToLogsOnError',
              }
              for c in o.spec.template.spec.initContainers
            ],
          },
        },
      },
      [if std.setMember(o.kind, std.set(['Alertmanager', 'Prometheus', 'ThanosRuler'])) then 'spec']+: {
        containers: [
          c {
            terminationMessagePolicy: 'FallbackToLogsOnError',
          }
          for c in o.spec.containers
        ],
        [if 'initContainers' in o.spec then 'initContainers']: [
          c {
            terminationMessagePolicy: 'FallbackToLogsOnError',
          }
          for c in o.spec.initContainers
        ],
      },
    },
    [k]: addTerminationMessagePolicy(o[k])
    for k in std.objectFields(o)
  },
}
