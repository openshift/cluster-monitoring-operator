local kp = (import 'kube-prometheus/kube-prometheus.libsonnet') +
           // NOTE: the `anti-affinity` package is actually the
           // `kube-prometheus` package checked out at a specific version
           // that includes https://github.com/coreos/prometheus-operator/pull/1935.
           (import 'anti-affinity/kube-prometheus-anti-affinity.libsonnet') +
           (import 'kube-prometheus/kube-prometheus-static-etcd.libsonnet') +
           {
             _config+:: {

               tlsCipherSuites: [
                 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',  // required by h2: http://golang.org/cl/30721
                 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',  // required by h2: http://golang.org/cl/30721

                 // 'TLS_RSA_WITH_RC4_128_SHA',            // insecure: https://access.redhat.com/security/cve/cve-2013-2566
                 // 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',       // insecure: https://access.redhat.com/articles/2548661
                 // 'TLS_RSA_WITH_AES_128_CBC_SHA',        // disabled by h2
                 // 'TLS_RSA_WITH_AES_256_CBC_SHA',        // disabled by h2
                 'TLS_RSA_WITH_AES_128_CBC_SHA256',
                 // 'TLS_RSA_WITH_AES_128_GCM_SHA256',     // disabled by h2
                 // 'TLS_RSA_WITH_AES_256_GCM_SHA384',     // disabled by h2
                 // 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',    // insecure: https://access.redhat.com/security/cve/cve-2013-2566
                 // 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',// disabled by h2
                 // 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',// disabled by h2
                 // 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',      // insecure: https://access.redhat.com/security/cve/cve-2013-2566
                 // 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', // insecure: https://access.redhat.com/articles/2548661
                 // 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',  // disabled by h2
                 // 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',  // disabled by h2
                 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
                 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',

                 // disabled by h2 means: https://github.com/golang/net/blob/e514e69ffb8bc3c76a71ae40de0118d794855992/http2/ciphers.go

                 // 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',   // TODO: Might not work with h2
                 // 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', // TODO: Might not work with h2
                 // 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305',    // TODO: Might not work with h2
                 // 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305',  // TODO: Might not work with h2
               ],

               imageRepos+:: {
                 openshiftOauthProxy: 'openshift/oauth-proxy',
                 prometheus: 'openshift/prometheus',
                 alertmanager: 'openshift/prometheus-alertmanager',
                 nodeExporter: 'openshift/prometheus-node-exporter',
               },
               versions+:: {
                 openshiftOauthProxy: 'v1.1.0',
               },
               etcd+:: {
                 ips: [],
                 clientCA: '',
                 clientKey: '',
                 clientCert: '',
                 serverName: '',
               },
             },
           } +
           (import 'rules.jsonnet') +
           (import 'prometheus-operator.jsonnet') +
           (import 'node-exporter.jsonnet') +
           (import 'kube-state-metrics.jsonnet') +
           (import 'grafana.jsonnet') +
           (import 'alertmanager.jsonnet') +
           (import 'prometheus.jsonnet') +
           (import 'cluster-monitoring-operator.jsonnet') +
           (import 'remove_runbook.libsonnet') + {
  _config+:: {
    namespace: 'openshift-monitoring',

    kubeSchedulerSelector: 'job="kube-controllers"',
    kubeControllerManagerSelector: 'job="kube-controllers"',
    namespaceSelector: 'namespace=~"(openshift-.*|kube-.*|default|logging)"',
  },
} + {
  local d = super.grafanaDashboards,
  grafanaDashboards:: {
    [k]: d[k]
    for k in std.objectFields(d)
    if !std.setMember(k, ['nodes.json', 'pods.json', 'statefulset.json'])
  },
};

{ ['prometheus-operator/' + name]: kp.prometheusOperator[name] for name in std.objectFields(kp.prometheusOperator) } +
{ ['node-exporter/' + name]: kp.nodeExporter[name] for name in std.objectFields(kp.nodeExporter) } +
{ ['kube-state-metrics/' + name]: kp.kubeStateMetrics[name] for name in std.objectFields(kp.kubeStateMetrics) } +
{ ['alertmanager/' + name]: kp.alertmanager[name] for name in std.objectFields(kp.alertmanager) } +
{ ['prometheus-k8s/' + name]: kp.prometheus[name] for name in std.objectFields(kp.prometheus) } +
{ ['grafana/' + name]: kp.grafana[name] for name in std.objectFields(kp.grafana) } +
{ ['cluster-monitoring-operator/' + name]: kp.clusterMonitoringOperator[name] for name in std.objectFields(kp.clusterMonitoringOperator) }
