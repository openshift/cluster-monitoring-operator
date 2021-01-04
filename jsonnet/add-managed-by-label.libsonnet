{
  addManagedByLabel(o): {
    local addLabel(o) = o {
      [if (o.kind != 'ConfigMapList' && o.kind != 'CustomResourceDefinition') then 'metadata']+: {
        labels+: {
          'app.kubernetes.io/managed-by': "cluster-monitoring-operator"
        },
      },
      // handle dashboards
      [if (o.kind == 'ConfigMapList') then 'items']: [
        i {
          metadata+: {
            labels+: {
              'app.kubernetes.io/managed-by': "cluster-monitoring-operator"
            }
          },
        }
        for i in super.items
      ]
    },
    [k]: addLabel(o[k])
    for k in std.objectFields(o)
  },
}
