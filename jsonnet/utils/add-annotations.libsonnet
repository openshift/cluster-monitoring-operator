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

  testFilePlaceholder(namespace, service, port):
    'xx_omitted_before_deploy__test_file_name:%s_%s_service_port_%d.yaml' % [namespace, service, port],

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

  addOptionalMonitoringCapabilityAnnotation(o): {
    local optionalMonitoringObjectKeysWithKind = std.set([
      // assets
      'Alertmanager,openshift-monitoring/main',
      'Alertmanager,openshift-user-workload-monitoring/user-workload',
      'ClusterRole,/alert-routing-edit',
      'ClusterRole,/alertmanager-main',
      'ClusterRole,/alertmanager-user-workload',
      'ClusterRole,/prometheus-user-workload',
      'ClusterRole,/prometheus-user-workload-operator',
      'ClusterRole,/thanos-ruler',
      'ClusterRoleBinding,/alertmanager-main',
      'ClusterRoleBinding,/alertmanager-user-workload',
      'ClusterRoleBinding,/prometheus-user-workload',
      'ClusterRoleBinding,/prometheus-user-workload-operator',
      'ClusterRoleBinding,/thanos-ruler',
      'ClusterRoleBinding,/thanos-ruler-monitoring',
      'ClusterRoleBinding,openshift-monitoring/alertmanager-main',
      'ClusterRoleBinding,openshift-user-workload-monitoring/alertmanager-user-workload',
      'ClusterRoleBinding,openshift-user-workload-monitoring/prometheus-user-workload',
      'ClusterRoleBinding,openshift-user-workload-monitoring/prometheus-user-workload-operator',
      'ClusterRoleBinding,openshift-user-workload-monitoring/thanos-ruler',
      'ClusterRoleBinding,openshift-user-workload-monitoring/thanos-ruler-monitoring',
      'ConfigMap,openshift-monitoring/alertmanager-trusted-ca-bundle',
      'ConfigMap,openshift-user-workload-monitoring/alertmanager-trusted-ca-bundle',
      'ConfigMap,openshift-user-workload-monitoring/prometheus-user-workload-trusted-ca-bundle',
      'ConfigMap,openshift-user-workload-monitoring/serving-certs-ca-bundle',
      'ConfigMap,openshift-user-workload-monitoring/user-workload-monitoring-config',
      'ConsolePlugin,/monitoring-plugin',
      'Deployment,openshift-monitoring/monitoring-plugin',
      'Deployment,openshift-user-workload-monitoring/prometheus-operator',
      'PodDisruptionBudget,openshift-monitoring/alertmanager-main',
      'PodDisruptionBudget,openshift-monitoring/monitoring-plugin',
      'PodDisruptionBudget,openshift-user-workload-monitoring/alertmanager-user-workload',
      'PodDisruptionBudget,openshift-user-workload-monitoring/prometheus-user-workload',
      'PodDisruptionBudget,openshift-user-workload-monitoring/thanos-ruler-user-workload',
      'Prometheus,openshift-user-workload-monitoring/user-workload',
      'PrometheusRule,openshift-monitoring/alertmanager-main-rules',
      'PrometheusRule,openshift-user-workload-monitoring/thanos-ruler',
      'Role,openshift-monitoring/monitoring-alertmanager-edit',
      'Role,openshift-monitoring/monitoring-alertmanager-view',
      'Role,openshift-user-workload-monitoring/monitoring-alertmanager-api-reader',
      'Role,openshift-user-workload-monitoring/monitoring-alertmanager-api-writer',
      'Role,openshift-user-workload-monitoring/prometheus-user-workload',
      'Role,openshift-user-workload-monitoring/prometheus-user-workload-config',
      'Role,openshift-user-workload-monitoring/user-workload-monitoring-config-edit',
      'RoleBinding,openshift-monitoring/alertmanager-prometheususer-workload',
      'RoleBinding,openshift-monitoring/alertmanager-thanos-ruler',
      'RoleBinding,openshift-user-workload-monitoring/alertmanager-user-workload-prometheususer-workload',
      'RoleBinding,openshift-user-workload-monitoring/prometheus-user-workload',
      'RoleBinding,openshift-user-workload-monitoring/prometheus-user-workload-config',
      'RoleBinding,openshift-user-workload-monitoring/user-workload-alertmanager-thanos-ruler',
      'Route,openshift-monitoring/alertmanager-main',
      'Route,openshift-user-workload-monitoring/federate',
      'Route,openshift-user-workload-monitoring/thanos-ruler',
      'Secret,openshift-monitoring/alertmanager-kube-rbac-proxy',
      'Secret,openshift-monitoring/alertmanager-kube-rbac-proxy-metric',
      'Secret,openshift-monitoring/alertmanager-kube-rbac-proxy-web',
      'Secret,openshift-monitoring/alertmanager-main',
      'Secret,openshift-user-workload-monitoring/alertmanager-kube-rbac-proxy',
      'Secret,openshift-user-workload-monitoring/alertmanager-kube-rbac-proxy-metric',
      'Secret,openshift-user-workload-monitoring/alertmanager-kube-rbac-proxy-tenancy',
      'Secret,openshift-user-workload-monitoring/alertmanager-user-workload',
      'Secret,openshift-user-workload-monitoring/kube-rbac-proxy-federate',
      'Secret,openshift-user-workload-monitoring/kube-rbac-proxy-metrics',
      'Secret,openshift-user-workload-monitoring/prometheus-operator-uwm-kube-rbac-proxy-config',
      'Secret,openshift-user-workload-monitoring/prometheus-user-workload-grpc-tls',
      'Secret,openshift-user-workload-monitoring/thanos-ruler-alertmanagers-config',
      'Secret,openshift-user-workload-monitoring/thanos-ruler-grpc-tls',
      'Secret,openshift-user-workload-monitoring/thanos-ruler-kube-rbac-proxy-metrics',
      'Secret,openshift-user-workload-monitoring/thanos-ruler-query-config',
      'Secret,openshift-user-workload-monitoring/thanos-user-workload-kube-rbac-proxy-web',
      'Service,openshift-monitoring/alertmanager-main',
      'Service,openshift-monitoring/monitoring-plugin',
      'Service,openshift-user-workload-monitoring/alertmanager-user-workload',
      'Service,openshift-user-workload-monitoring/prometheus-operator',
      'Service,openshift-user-workload-monitoring/prometheus-user-workload',
      'Service,openshift-user-workload-monitoring/prometheus-user-workload-thanos-sidecar',
      'Service,openshift-user-workload-monitoring/thanos-ruler',
      'ServiceAccount,openshift-monitoring/alertmanager-main',
      'ServiceAccount,openshift-monitoring/monitoring-plugin',
      'ServiceAccount,openshift-user-workload-monitoring/alertmanager-user-workload',
      'ServiceAccount,openshift-user-workload-monitoring/prometheus-operator',
      'ServiceAccount,openshift-user-workload-monitoring/prometheus-user-workload',
      'ServiceAccount,openshift-user-workload-monitoring/thanos-ruler',
      'ServiceMonitor,openshift-monitoring/alertmanager-main',
      'ServiceMonitor,openshift-user-workload-monitoring/alertmanager-user-workload',
      'ServiceMonitor,openshift-user-workload-monitoring/prometheus-operator',
      'ServiceMonitor,openshift-user-workload-monitoring/prometheus-user-workload',
      'ServiceMonitor,openshift-user-workload-monitoring/thanos-ruler',
      'ServiceMonitor,openshift-user-workload-monitoring/thanos-sidecar',
      'ThanosRuler,openshift-user-workload-monitoring/user-workload',
      'ValidatingWebhookConfiguration,/alertmanagerconfigs.openshift.io',

      // manifests
      'ConfigMap,openshift-config-managed/dashboard-cluster-total',
      'ConfigMap,openshift-config-managed/dashboard-k8s-resources-cluster',
      'ConfigMap,openshift-config-managed/dashboard-k8s-resources-namespace',
      'ConfigMap,openshift-config-managed/dashboard-k8s-resources-node',
      'ConfigMap,openshift-config-managed/dashboard-k8s-resources-pod',
      'ConfigMap,openshift-config-managed/dashboard-k8s-resources-workload',
      'ConfigMap,openshift-config-managed/dashboard-k8s-resources-workloads-namespace',
      'ConfigMap,openshift-config-managed/dashboard-namespace-by-pod',
      'ConfigMap,openshift-config-managed/dashboard-node-cluster-rsrc-use',
      'ConfigMap,openshift-config-managed/dashboard-node-rsrc-use',
      'ConfigMap,openshift-config-managed/dashboard-pod-total',
      'ConfigMap,openshift-config-managed/dashboard-prometheus',
      'CustomResourceDefinition,/alertingrules.monitoring.openshift.io',
      'CustomResourceDefinition,/alertmanagerconfigs.monitoring.coreos.com',
      'CustomResourceDefinition,/alertmanagers.monitoring.coreos.com',
      'CustomResourceDefinition,/alertrelabelconfigs.monitoring.openshift.io',
      'CustomResourceDefinition,/probes.monitoring.coreos.com',
      'CustomResourceDefinition,/thanosrulers.monitoring.coreos.com',
      'Role,openshift-monitoring/cluster-monitoring-operator-alert-customization',
    ]),

    local optionalMonitoringCapabilityAnnotation = 'capability.openshift.io/name',
    local optionalMonitoringCapabilityAnnotationValue = 'OptionalMonitoring',
    local lookupObjectKeyWithKind(o) = std.setMember(
      o.kind + ',' + (if std.objectHas(o.metadata, 'namespace') then o.metadata.namespace else '') + '/' + o.metadata.name,
      optionalMonitoringObjectKeysWithKind
    ),
    local maybeAppendToAnnotationValue(v) =
      if std.objectHas(v, 'annotations') && std.objectHas(v.annotations, optionalMonitoringCapabilityAnnotation) then
        v.annotations[optionalMonitoringCapabilityAnnotation] + '+' + optionalMonitoringCapabilityAnnotationValue
      else
        optionalMonitoringCapabilityAnnotationValue,

    local addAnnotation(o) = o {
      [if o.kind == 'RoleBindingList' || o.kind == 'RoleList' || o.kind == 'ConfigMapList' then 'items']: [
        if lookupObjectKeyWithKind(i) then i {
          metadata+: {
            annotations+: {
              [optionalMonitoringCapabilityAnnotation]: maybeAppendToAnnotationValue(i.metadata),
            },
          },
        }
        else i
        for i in super.items
      ],
      [if std.objectHas(o, 'metadata') /* == not a list */ && lookupObjectKeyWithKind(o) then 'metadata']+: {
        annotations+: {
          [optionalMonitoringCapabilityAnnotation]: maybeAppendToAnnotationValue(o.metadata),
        },
      },
    },
    [k]: addAnnotation(o[k])
    for k in std.objectFields(o)
  },

  addAnnotations(o): $.addOptionalMonitoringCapabilityAnnotation($.addWorkloadAnnotation($.addReleaseAnnotation(o))),
}
