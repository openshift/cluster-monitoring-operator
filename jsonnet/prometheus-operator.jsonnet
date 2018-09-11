{
  prometheusOperator+:: {
    deployment+:
      {
        spec+: {
          template+: {
            spec+: {
              securityContext: {},
              priorityClassName: 'system-cluster-critical',

              containers:
                std.map(
                  function(c) c {
                    resources: {},
                    args+: ['--namespace=' + $._config.namespace],
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
