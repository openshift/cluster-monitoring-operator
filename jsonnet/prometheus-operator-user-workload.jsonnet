{
  prometheusOperatorUserWorkload:: $.prometheusOperator + {
    namespace:: $._config.namespaceUserWorkload,

    '0alertmanagerCustomResourceDefinition':: {},
    '0prometheusCustomResourceDefinition':: {},
    '0servicemonitorCustomResourceDefinition':: {},
    '0podmonitorCustomResourceDefinition':: {},
    '0prometheusruleCustomResourceDefinition':: {},

    clusterRole+: {
      metadata+: {
        name: "prometheus-user-workload-operator",
      },
    },

    clusterRoleBinding+: {
      metadata+: {
        name: "prometheus-user-workload-operator",
      },
      roleRef+: {
        name: "prometheus-user-workload-operator",
      },
    },

    deployment+:
      {
        spec+: {
          template+: {
            spec+: {
              nodeSelector+: {
                'node-role.kubernetes.io/master': '',
              },
              tolerations: [
                {
                  key: 'node-role.kubernetes.io/master',
                  operator: 'Exists',
                  effect: 'NoSchedule',
                },
              ],
              securityContext: {},
              priorityClassName: 'system-cluster-critical',
              containers:
                std.map(
                  function(c) c {
                    args+: [
                        '--deny-namespaces=' + $._config.namespace,
                        '--prometheus-instance-namespaces=' + $._config.namespaceUserWorkload,
                        '--alertmanager-instance-namespaces=' + $._config.namespaceUserWorkload,
                        '--manage-crds=false',
                        '--config-reloader-cpu=0',
                    ],
                    securityContext: {},
                    resources: {
                      requests: {
                        memory: '60Mi',
                        cpu: '10m',
                      },
                    },
                    terminationMessagePolicy: 'FallbackToLogsOnError',
                  },
                  super.containers,
                ),
            },
          },
        },
      },
  },
}