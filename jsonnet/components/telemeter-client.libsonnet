local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';
local withDescription = (import '../utils/add-annotations.libsonnet').withDescription;

function(params) {
  local cfg = params,
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
      telemeterClient+:: {
        from: 'https://prometheus-k8s.%(namespace)s.svc:9091' % cfg,
      },
    },
  },

  prometheusRule: tc.telemeterClient.prometheusRule,
  clusterRoleBindingView: tc.telemeterClient.clusterRoleBindingView,
  clusterRoleBinding: tc.telemeterClient.clusterRoleBinding,
  clusterRole: tc.telemeterClient.clusterRole,
  serviceAccount: tc.telemeterClient.serviceAccount,
  service: tc.telemeterClient.service {
    metadata+: {
      annotations+: withDescription('Expose the `/metrics` endpoint on port %d. This port is for internal use, and no other usage is guaranteed.' % $.service.spec.ports[0].port),
    },
  },
  serviceMonitor: tc.telemeterClient.serviceMonitor {
    spec+: {
      endpoints: [
        {
          port: 'https',
          interval: '30s',
          scheme: 'https',
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
          annotations+: {
            'openshift.io/required-scc': 'restricted-v2',
          },
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
  networkPolicy: {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: {
      annotations: {
        'include.release.openshift.io/hypershift': 'true',
        'include.release.openshift.io/ibm-cloud-managed': 'true',
        'include.release.openshift.io/self-managed-high-availability': 'true',
        'include.release.openshift.io/single-node-developer': 'true',
      },
      name: 'telemeter-client-access',
      namespace: cfg.namespace,
    },
    spec: {
      podSelector: {
        matchLabels: {
          'app.kubernetes.io/name': 'telemeter-client',
        },
      },
      policyTypes: [
        'Ingress',
        'Egress',
      ],
      ingress: [
        {
          ports: [
            {
              port: '8443',
              protocol: 'TCP',
            },
          ],
        },
      ],
      egress: [
        {},
      ],
    },
  },
}
