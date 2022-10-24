local tlsVolumeName = 'prometheus-operator-tls';

local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';

local operator = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/prometheus-operator.libsonnet';
local conversionWebhook = import 'github.com/prometheus-operator/prometheus-operator/jsonnet/prometheus-operator/conversion.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';

function(params)
  local cfg = params;
  operator(cfg) + {
    '0alertmanagerConfigCustomResourceDefinition'+:
      // Add v1beta1 AlertmanagerConfig version.
      (import 'github.com/prometheus-operator/prometheus-operator/jsonnet/prometheus-operator/alertmanagerconfigs-v1beta1-crd.libsonnet') +
      // Enable conversion webhook.
      conversionWebhook(cfg.conversionWebhook),

    kubeRbacProxySecret: generateSecret.staticAuthSecret(cfg.namespace, cfg.commonLabels, 'prometheus-operator-kube-rbac-proxy-config'),
    deployment+: {
      metadata+: {
        labels+: {
          'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
        },
      },
      spec+: {
        template+: {
          metadata+: {
            labels+: {
              'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
            },
          },
          spec+: {
            nodeSelector+: {
              'node-role.kubernetes.io/master': '',
            },
            tolerations: [{
              key: 'node-role.kubernetes.io/master',
              operator: 'Exists',
              effect: 'NoSchedule',
            }],
            securityContext: {},
            priorityClassName: 'system-cluster-critical',
            containers:
              std.map(
                function(c)
                  if c.name == 'prometheus-operator' then
                    // TODO(simonpasquier): add readiness/liveness probes once
                    // upstream prometheus-operator supports /healthz endpoint
                    // without requiring client TLS authentication.
                    c {
                      args+: [
                        '--prometheus-instance-namespaces=' + cfg.namespace,
                        '--thanos-ruler-instance-namespaces=' + cfg.namespace,
                        '--alertmanager-instance-namespaces=' + cfg.namespace,
                        '--config-reloader-cpu-limit=0',
                        '--config-reloader-memory-limit=0',
                        '--config-reloader-cpu-request=1m',
                        '--config-reloader-memory-request=10Mi',
                        '--web.listen-address=127.0.0.1:8080',
                      ],
                      ports: [],
                      resources: {
                        requests: {
                          memory: '150Mi',
                          cpu: '5m',
                        },
                      },
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                    }
                  else if c.name == 'kube-rbac-proxy' then
                    // TODO(simonpasquier): remove kube-rbac-proxy and
                    // configure the proper client CA + name in the prometheus
                    // operator container directly (once prometheus operator
                    // upstream supports name verification).
                    c {
                      args: [
                        '--logtostderr',
                        '--secure-listen-address=:8443',
                        '--tls-cipher-suites=' + cfg.tlsCipherSuites,
                        '--upstream=http://localhost:8080/',
                        '--tls-cert-file=/etc/tls/private/tls.crt',
                        '--tls-private-key-file=/etc/tls/private/tls.key',
                        '--client-ca-file=/etc/tls/client/client-ca.crt',
                        '--config-file=/etc/kube-rbac-policy/config.yaml',
                      ],
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                      volumeMounts: [
                        {
                          mountPath: '/etc/tls/private',
                          name: tlsVolumeName,
                          readOnly: true,
                        },
                        {
                          mountPath: '/etc/tls/client',
                          name: 'metrics-client-ca',
                          readOnly: true,
                        },
                        {
                          mountPath: '/etc/kube-rbac-policy',
                          name: 'prometheus-operator-kube-rbac-proxy-config',
                          readOnly: true,
                        },
                      ],
                      securityContext: {},
                      resources: {
                        requests: {
                          memory: '15Mi',
                          cpu: '1m',
                        },
                      },
                    }
                  else
                    c,
                super.containers,
              ),
            volumes+: [
              {
                name: tlsVolumeName,
                secret: {
                  secretName: 'prometheus-operator-tls',
                },

              },
              {
                name: 'prometheus-operator-kube-rbac-proxy-config',
                secret: {
                  secretName: 'prometheus-operator-kube-rbac-proxy-config',
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

    service+: {
      metadata+: {
        annotations+: {
          'service.beta.openshift.io/serving-cert-secret-name': 'prometheus-operator-tls',
        },
      },
    },

    serviceMonitor+: {
      spec+: {
        endpoints: [
          {
            honorLabels: true,
            bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            port: 'https',
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

    // TODO(simonpasquier): remove once 4.13 branch opens.
    operatorCertsCaBundle: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: {
        name: 'operator-certs-ca-bundle',
        namespace: cfg.namespace,
      },
    },
  }
