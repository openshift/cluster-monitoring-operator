local generateSecret = import '../utils/generate-secret.libsonnet';
function(params) {
  local cfg = params,
  local osm = (import 'github.com/openshift/openshift-state-metrics/jsonnet/openshift-state-metrics.libsonnet') + {
    _config+:: {
      namespace: cfg.namespace,
      versions: {
        openshiftStateMetrics: 'latest',
        kubeRbacProxy: 'latest',
      },
      openshiftStateMetrics+:: {
        baseMemory: '32Mi',
      },
    },
  },

  // Remapping everything as this is the only way I could think of without refactoring imported library
  // This shouldn't make much difference as openshift-state-metrics project is scheduled for deprecation
  clusterRoleBinding: osm.openshiftStateMetrics.clusterRoleBinding,
  clusterRole: osm.openshiftStateMetrics.clusterRole,
  deployment: osm.openshiftStateMetrics.deployment {
    metadata+: {
      labels+: {
        'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
      } + cfg.commonLabels + osm._config.commonLabels,
    },
    spec+: {
      template+: {
        metadata+: {
          labels+: {
            'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
          } + cfg.commonLabels,
        },
        spec+: {
          containers:
            std.map(
              function(c)
                if c.name == 'kube-rbac-proxy-main' || c.name == 'kube-rbac-proxy-self' then
                  c {
                    image: cfg.kubeRbacProxyImage,
                    args+: [
                      '--config-file=/etc/kube-rbac-policy/config.yaml',
                    ],
                    volumeMounts+: [
                      {
                        mountPath: '/etc/kube-rbac-policy',
                        name: 'openshift-state-metrics-kube-rbac-proxy-config',
                        readOnly: true,
                      },
                    ],
                  }
                else
                  c,
              super.containers,
            ),
          volumes+: [
            {
              name: 'openshift-state-metrics-kube-rbac-proxy-config',
              secret: {
                secretName: 'openshift-state-metrics-kube-rbac-proxy-config',
              },
            },
          ],
        },
      },
    },
  },
  kubeRbacProxySecret: generateSecret.staticAuthSecret(cfg.namespace, cfg.commonLabels, 'openshift-state-metrics-kube-rbac-proxy-config'),
  serviceAccount: osm.openshiftStateMetrics.serviceAccount,
  service: osm.openshiftStateMetrics.service,
  serviceMonitor: osm.openshiftStateMetrics.serviceMonitor,

}
