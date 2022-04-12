{
  addBearerTokenToServiceMonitors(o): {
    local addBearerToken(o) = o {
      [if o.kind == 'ServiceMonitor' && o.metadata.name != 'etcd' then 'spec']+: {
        endpoints: [
          if std.objectHas(e, 'scheme') && e.scheme == 'https' then
            e {
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            }
          else
            e
          for e in super.endpoints
        ],
      },
    },
    [k]: addBearerToken(o[k])
    for k in std.objectFieldsAll(o)
  },
}
