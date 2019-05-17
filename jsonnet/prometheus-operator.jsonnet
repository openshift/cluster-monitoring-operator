{
  prometheusOperator+:: {
    deployment+:
      {
        spec+: {
          template+: {
            spec+: {
              securityContext: {},
              priorityClassName: 'system-cluster-critical',
              resources: {
                requests: {
                  memory: '100Mi',
                  cpu: '10m',
                },
              },
              containers:
                std.map(
                  function(c) c {
                    resources: {},
                    args+: ['--namespaces=' + $._config.namespace],
                    securityContext: {},
                  },
                  super.containers,
                ),
            },
          },
        },
      },
  },
}
