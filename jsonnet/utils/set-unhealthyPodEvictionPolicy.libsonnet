{
  setUnhealthyPodEvictionPolicy(o): o {
    local addUnhealthyPodEvictionPolicy(o) = o {
      [if std.setMember(o.kind, std.set(['PodDisruptionBudget'])) then 'spec']+: {
        unhealthyPodEvictionPolicy: 'AlwaysAllow',
      },
    },
    [k]: addUnhealthyPodEvictionPolicy(o[k])
    for k in std.objectFields(o)
  },
}
