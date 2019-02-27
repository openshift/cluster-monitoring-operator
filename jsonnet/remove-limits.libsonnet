{
  removeLimits(o): {
    local removeLimit(o) = o {
      [if std.setMember(o.kind, ['DaemonSet', 'Deployment', 'ReplicaSet']) then 'spec']+: {
        template+: {
          spec+: {
            containers: [
              c {
                [if std.objectHas(c, 'resources') then 'resources']+: {
                  limits:: null,
                },
              }
              for c in super.containers
            ],
          },
        },
      },
    },
    [k]: removeLimit(o[k])
    for k in std.objectFields(o)
  },
}
