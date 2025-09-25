{
  removeImageLocations(o): {
    local removeImageLocation(o) = o {
      [if std.setMember(o.kind, std.set(['DaemonSet', 'Deployment'])) && o.metadata.name != 'cluster-monitoring-operator' then 'spec']+: {
        template+: {
          spec+: {
            containers: [
              c {
                image: '',
              }
              for c in super.containers
            ],
            [if std.objectHas(o.spec.template.spec, 'initContainers') then 'initContainers']: [
              c {
                image: '',
              }
              for c in super.initContainers
            ],
          },
        },
      },
      [if std.setMember(o.kind, std.set(['Prometheus', 'Alertmanager', 'ThanosRuler'])) then 'spec']+: {
        image: '',
        [if std.objectHas(o.spec, 'thanos') then 'thanos']+: {
          image: '',
        },
        containers: [
          c {
            image: '',
          }
          for c in super.containers
        ],
        [if std.objectHas(o.spec, 'initContainers') then 'initContainers']: [
          c {
            image: '',
          }
          for c in super.initContainers
        ],
      },
    },
    [k]: removeImageLocation(o[k])
    for k in std.objectFields(o)
  },
}
