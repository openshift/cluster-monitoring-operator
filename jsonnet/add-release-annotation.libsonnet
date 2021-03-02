{
  addReleaseAnnotation(o): {
    local addAnnotation(o) = o {
      [if (o.kind == 'CustomResourceDefinition') then 'metadata']+: {
        annotations+: {
          'include.release.openshift.io/ibm-cloud-managed': 'true',
          'include.release.openshift.io/self-managed-high-availability': 'true',
          'include.release.openshift.io/single-node-developer': 'true',
        },
      },
      [if (o.kind == 'ConfigMapList') then 'items']: [
        i {
          metadata+: {
            annotations+: {
              'include.release.openshift.io/ibm-cloud-managed': 'true',
              'include.release.openshift.io/self-managed-high-availability': 'true',
              'include.release.openshift.io/single-node-developer': 'true',
            },
          },
        }
        for i in super.items
      ],
    },
    [k]: addAnnotation(o[k])
    for k in std.objectFields(o)
  },
}
