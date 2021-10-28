// I didn't invest much time into this file since telemeter-client is scheduled for deprecation when we enable remote-write in prometheus
local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';

function(params) {
  local cfg = params,
  //local osm = import 'github.com/openshift/openshift-state-metrics/jsonnet/openshift-state-metrics.libsonnet';
  local tc = (import 'github.com/openshift/telemeter/jsonnet/telemeter/client.libsonnet') + {
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
    },
  },

  // Remapping everything as this is the only way I could think of without refactoring imported library
  clusterRoleBindingView: tc.telemeterClient.clusterRoleBindingView,
  clusterRoleBinding: tc.telemeterClient.clusterRoleBinding,
  clusterRole: tc.telemeterClient.clusterRole,
  serviceAccount: tc.telemeterClient.serviceAccount,
  service: tc.telemeterClient.service,
  serviceMonitor: tc.telemeterClient.serviceMonitor {
    spec+: {
      endpoints: [
        {
          port: 'https',
          interval: '30s',
          scheme: 'https',
          tlsConfig: {
            caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
            serverName: 'server-name-replaced-at-runtime',
            certFile: '/etc/prometheus/secrets/metrics-client-certs/tls.crt',
            keyFile: '/etc/prometheus/secrets/metrics-client-certs/tls.key',
          },
        },
      ],
    },
  },
  secret: tc.telemeterClient.secret,
  servingCertsCABundle: tc.telemeterClient.servingCertsCABundle,
  kubeRbacProxySecret: generateSecret.staticAuthSecret(cfg.namespace, cfg.commonLabels, 'telemeter-client-kube-rbac-proxy-config'),
  deployment: tc.telemeterClient.deployment {
    metadata+: {
      labels+: {
        'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
      } + cfg.commonLabels + tc._config.commonLabels,
    },
    spec+: {
      template+: {
        metadata+: {
          labels+: {
            'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
          } + cfg.commonLabels,
        },
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
                else if c.name == 'kube-rbac-proxy' then
                  c {
                    image: cfg.kubeRbacProxyImage,
                    args+: [
                      '--config-file=/etc/kube-rbac-policy/config.yaml',
                      '--client-ca-file=/etc/tls/client/client-ca.crt',
                    ],
                    volumeMounts+: [
                      {
                        mountPath: '/etc/kube-rbac-policy',
                        name: 'secret-' + $.kubeRbacProxySecret.metadata.name,
                        readOnly: true,
                      },
                      {
                        mountPath: '/etc/tls/client',
                        name: 'metrics-client-ca',
                        readOnly: true,
                      },
                    ],
                  }
                else
                  c,
              super.containers,
            ),
          volumes+: [
            {
              name: 'secret-' + $.kubeRbacProxySecret.metadata.name,
              secret: {
                secretName: $.kubeRbacProxySecret.metadata.name,
              },
            },
            {
              name: 'metrics-client-ca',
              configMap: {
                name: 'metrics-client-ca',
              },
            },
          ],
        },
      },
    },
  },

  trustedCaBundle: generateCertInjection.trustedCNOCaBundleCM(cfg.namespace, 'telemeter-trusted-ca-bundle'),
}
