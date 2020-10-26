{
  addReleaseAnnotation(o): {
    local addAnnotation(o) = o {
      [if (o.kind == 'CustomResourceDefinition') then 'metadata']+: {
        annotations+: {
          'include.release.openshift.io/self-managed-high-availability': "true"
        },
      },
      [if (o.kind == 'ConfigMapList') then 'items']: [
        i {
          metadata+: {
            annotations+: {
              'include.release.openshift.io/self-managed-high-availability': "true"
            }
          },
        }
        for i in super.items
      ]
    },
    [k]: addAnnotation(o[k])
    for k in std.objectFields(o)
  },
}
