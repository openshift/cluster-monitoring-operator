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
