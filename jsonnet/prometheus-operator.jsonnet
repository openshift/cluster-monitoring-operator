{
  prometheusOperator+:: {
    deployment+:
      {
        spec+: {
          template+: {
            spec+: {
              securityContext: {},

              containers:
                std.map(
                  function(c) c { resources: {} },
                  super.containers,
                ),
            },
          },
        },
      },
  },
}
