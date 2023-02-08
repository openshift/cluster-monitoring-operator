{
  configureAuthenticationForMonitors(o): {
    local configureAuthentication(o) = o {
      [if (o.kind == 'ServiceMonitor' && !std.startsWith(o.metadata.name, 'etcd')) || o.kind == 'PodMonitor' then 'spec']+: {
        [if o.kind == 'ServiceMonitor' then 'endpoints' else 'podMetricsEndpoints']: [
          if std.objectHas(e, 'scheme') && e.scheme == 'https' then
            e {
              bearerTokenFile: '',
              tlsConfig+: {
                            certFile: '/etc/prometheus/secrets/metrics-client-certs/tls.crt',
                            keyFile: '/etc/prometheus/secrets/metrics-client-certs/tls.key',
                            insecureSkipVerify: false,
                          } +
                          if !(std.objectHas(o.metadata.labels, 'app.kubernetes.io/name') && o.metadata.labels['app.kubernetes.io/name'] == 'kubelet') then
                            {
                              caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                              // For setting serverName the following logic is applied:
                              // 1. Default behaviour for the majority of ServiceMonitors
                              // 2. ServiceMonitors that end with -minimal or -$FUTURE_SCRAPE_PROFILE cannot just set
                              // server name with o.metadata.name, thus we strip - and $PROFILE_NAME from o.metadata.name
                              // 3. PrometheusThanos sidecar also have to be handled in a special fashion due to the
                              // ServiceAccount having a different name than the ServiceMonitor
                              serverName: std.format('%s.%s.svc',
                                                     [
                                                       if o.metadata.name != 'thanos-sidecar' then
                                                         if !std.objectHas(o.metadata.labels, 'monitoring.openshift.io/scrape-profile') || o.metadata.labels['monitoring.openshift.io/scrape-profile'] == 'full' then
                                                           o.metadata.name
                                                         else
                                                           std.rstripChars(o.metadata.name, '-' + o.metadata.labels['monitoring.openshift.io/scrape-profile'])
                                                       else
                                                         'prometheus-' + o.metadata.labels['app.kubernetes.io/instance'] + '-' + o.metadata.name,
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
