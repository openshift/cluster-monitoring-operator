{
  addReleaseAnnotation(o): {
    local addAnnotation(o) = o {
      [if (o.kind == 'CustomResourceDefinition') then 'metadata']+: {
        annotations+: {
          'include.release.openshift.io/ibm-cloud-managed': 'true',
          'include.release.openshift.io/hypershift': 'true',
          'include.release.openshift.io/self-managed-high-availability': 'true',
          'include.release.openshift.io/single-node-developer': 'true',
        },
      },
      [if (o.kind == 'ConfigMapList') then 'items']: [
        i {
          metadata+: {
            annotations+: {
              'include.release.openshift.io/ibm-cloud-managed': 'true',
              'include.release.openshift.io/hypershift': 'true',
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
      [if std.setMember(o.kind, std.set(['DaemonSet', 'Deployment'])) then 'spec']+: {
        template+: {
          metadata+: {
            annotations+: annotation,
          },
        },
      },
      [if std.setMember(o.kind, std.set(['Alertmanager', 'Prometheus', 'ThanosRuler'])) then 'spec']+:
        {
          podMetadata+: {
            annotations+: annotation,
          },
        },
    },
    [k]: addAnnotation(o[k])
    for k in std.objectFields(o)
  },

  withDescription(s): {
    'openshift.io/description': std.rstripChars(s, '\n'),
  },

  requiredRoles(roles, namespace=''):
    assert std.length(roles) > 0 : 'needs at least one role';

    local buildRoleString(v) =
      if std.isArray(v) then
        assert std.length(v) == 2 : 'needs one role + one description';
        '`%s` role (%s)' % [v[0], v[1]]
      else
        '`%s` role' % v;

    'Granting access requires binding a user to the %s in the %sproject.' % [
      std.join(' or ', std.map(buildRoleString, roles)),
      if namespace != '' then '`%s` ' % namespace else '',
    ],

  requiredClusterRoles(roles, clusterRoleBinding, namespace=''):
    assert std.length(roles) > 0 : 'needs at least one cluster role';

    local buildRoleString(v) =
      if std.isArray(v) then
        assert std.length(v) == 2 : 'needs at one cluster role + one description';
        '`%s` cluster role (%s)' % [v[0], v[1]]
      else
        '`%s` cluster role' % v;

    local s = 'Granting access requires binding a user to the %s' % [
      std.join(' or ', std.map(buildRoleString, roles)),
    ];
    if clusterRoleBinding then
      s + '.'
    else if namespace != '' then
      s + ' in the `%s` project.'
    else
      s + ' in the project.',

  addAnnotations(o): $.addWorkloadAnnotation(
    $.addReleaseAnnotation(o)
  ),
}
