// I didn't invest much time into this file since telemeter-client is scheduled for deprecation when we enable remote-write in prometheus

function(params) {
  local cfg = params,
  //local osm = import 'github.com/openshift/openshift-state-metrics/jsonnet/openshift-state-metrics.libsonnet';
  local tc = (import 'telemeter-client/client.libsonnet') + {
    _config+:: {
      namespace: cfg.namespace,
      tlsCipherSuites: [
        // List from https://github.com/prometheus-operator/kube-prometheus/blob/master/jsonnet/kube-prometheus/components/kube-rbac-proxy.libsonnet
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305',
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305',
      ],
      versions+: {
        kubeRbacProxy: 'latest',
      },
    },
  },

  // Remapping everything as this is the only way I could think of without refactoring imported library
  clusterRoleBindingView: tc.telemeterClient.clusterRoleBindingView,
  clusterRoleBinding: tc.telemeterClient.clusterRoleBinding,
  clusterRole: tc.telemeterClient.clusterRole,
  serviceAccount: tc.telemeterClient.serviceAccount,
  service: tc.telemeterClient.service,
  serviceMonitor: tc.telemeterClient.serviceMonitor,
  secret: tc.telemeterClient.secret,
  servingCertsCABundle: tc.telemeterClient.servingCertsCABundle,
  deployment: tc.telemeterClient.deployment {
    spec+: {
      template+: {
        spec+: {
          containers:
            std.map(
              function(c)
                if c.name == 'reload' then
                  c {
                    args: std.map(
                      function(a)
                        std.strReplace(std.strReplace(a, '--webhook-url=', '--reload-url='), '--volume-dir=', '--watched-dir=')
                      ,
                      c.args,
                    ),
                  }
                else
                  c,
              super.containers,
            ),
        },
      },
    },
  },

  trustedCaBundle: {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      name: 'telemeter-trusted-ca-bundle',
      namespace: cfg.namespace,
      labels: {
        'config.openshift.io/inject-trusted-cabundle': 'true',
      },
    },
    data: {
      'ca-bundle.crt': '',
    },
  },
}
