{
  prometheusOperator+:: {
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
                    args+: ['--namespaces=' + $._config.namespace],
                    securityContext: {},
                    resources: {
                      requests: {
                        memory: '60Mi',
                        cpu: '10m',
                      },
                    },
                  },
                  super.containers,
                ),
            },
          },
        },
      },
  },
}
