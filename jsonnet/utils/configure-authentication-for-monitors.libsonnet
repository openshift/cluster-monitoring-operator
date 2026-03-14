{
  configureAuthenticationForMonitors(o): {
    local configureAuthentication(o) = o {
      [if o.kind == 'ServiceMonitor' || o.kind == 'PodMonitor' then 'spec']+: {
        scrapeClass: 'tls-client-certificate-auth',
        [if o.kind == 'ServiceMonitor' then 'endpoints' else 'podMetricsEndpoints']: [
          if std.objectHas(e, 'scheme') && e.scheme == 'https' then
            e {
              bearerTokenFile: '',
              tlsConfig+:
                { insecureSkipVerify: false } +
                if !(std.objectHas(o.metadata.labels, 'app.kubernetes.io/name') && o.metadata.labels['app.kubernetes.io/name'] == 'kubelet') then
                  {
                    // For setting serverName the following logic is applied:
                    // 1. The name of the ServiceMonitor for the Prometheus thanos sidecar doesn't match
                    //    the Service's name which has the following format:
                    //      "prometheus-<PROMETHEUS_INSTANCE>-thanos-sidecar"
                    //    where PROMETHEUS_INSTANCE is either "k8s" or "user-workload"
                    // 2. ServiceMonitors that adopted CollectionProfiles have a "-<COLLECTION_PROFILE>" suffix
                    //    which should be stripped from the service monitor's name to get the Service's name.
                    // 3. Otherwise the name of the ServiceMonitor is equal to the name of the Service.
                    serverName: std.format('%s.%s.svc',
                                           [
                                             if o.metadata.name == 'thanos-sidecar' then
                                               std.format('prometheus-%s-thanos-sidecar', o.metadata.labels['app.kubernetes.io/instance'])
                                             else
                                               if std.objectHas(o.metadata.labels, 'monitoring.openshift.io/collection-profile') then
                                                 std.rstripChars(o.metadata.name, '-' + o.metadata.labels['monitoring.openshift.io/collection-profile'])
                                               else
                                                 o.metadata.name,
                                             o.metadata.namespace,
                                           ]),
                  }
                else
                  {},
            }
          else
            e
          for e in super.endpoints
        ],
      },
    },
    [k]: configureAuthentication(o[k])
    for k in std.objectFieldsAll(o)
  },
}
