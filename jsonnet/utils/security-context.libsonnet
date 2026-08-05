{
  enableReadOnlyRootFilesystem(o): o {
    local enableReadOnlyRootFilesystem(o) = o {
      [if std.setMember(o.kind, std.set(['DaemonSet', 'Deployment'])) then 'spec']+: {
        template+: {
          spec+: {
            containers: [
              c {
                securityContext+: { readOnlyRootFilesystem: true },
              }
              for c in o.spec.template.spec.containers
            ],
            [if 'initContainers' in o.spec.template.spec then 'initContainers']: [
              c {
                securityContext+: { readOnlyRootFilesystem: true },
              }
              for c in o.spec.template.spec.initContainers
            ],
          },
        },
      },
      [if std.setMember(o.kind, std.set(['Alertmanager', 'Prometheus', 'ThanosRuler'])) then 'spec']+: {
        containers: [
          c {
            securityContext+: { readOnlyRootFilesystem: true },
          }
          for c in o.spec.containers
        ],
        [if 'initContainers' in o.spec then 'initContainers']: [
          c {
            securityContext+: { readOnlyRootFilesystem: true },
          }
          for c in o.spec.initContainers
        ],
      },
    },
    [k]: enableReadOnlyRootFilesystem(o[k])
    for k in std.objectFields(o)
  },
}
