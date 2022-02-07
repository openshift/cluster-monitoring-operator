local tlsVolumeName = 'prometheus-operator-tls';
local operator = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/prometheus-operator.libsonnet';

function(params)
  local cfg = params;
  operator(cfg) + {
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
              std.filterMap(
                function(c) c.name != 'kube-rbac-proxy',
                function(c)
                  if c.name == 'prometheus-operator' then
                    c {
                      args+: [
                        '--prometheus-instance-namespaces=' + cfg.namespace,
                        '--thanos-ruler-instance-namespaces=' + cfg.namespace,
                        '--alertmanager-instance-namespaces=' + cfg.namespace,
                        '--config-reloader-cpu-limit=0',
                        '--config-reloader-memory-limit=0',
                        '--web.enable-tls=true',
                        '--web.listen-address=:8443',
                        '--web.tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305',
                        '--web.tls-min-version=VersionTLS12',
                        '--web.client-ca-file=/etc/tls/client/client-ca.crt',
                      ],
                      securityContext: {},
                      resources: {
                        requests: {
                          memory: '150Mi',
                          cpu: '5m',
                        },
                      },
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                      volumeMounts+: [
                        {
                          mountPath: '/etc/tls/private',
                          name: tlsVolumeName,
                          readOnly: false,
                        },
                        {
                          mountPath: '/etc/tls/client',
                          name: 'metrics-client-ca',
                          readOnly: false,
                        },
                      ],
                      ports: [
                        {
                          containerPort: 8443,
                          name: 'https',
                        },
                      ],
                    }
                  else c,
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

    prometheusRuleValidatingWebhook: {
      apiVersion: 'admissionregistration.k8s.io/v1',
      kind: 'ValidatingWebhookConfiguration',
      metadata: {
        name: 'prometheusrules.openshift.io',
        labels: {
          'app.kubernetes.io/component': 'controller',
          'app.kubernetes.io/name': 'prometheus-operator',
          //'app.kubernetes.io/version': $._config.versions.prometheusOperator, //FIXME(paulfantom)
        },
        annotations: {
          'service.beta.openshift.io/inject-cabundle': true,
        },
      },
      webhooks: [
        {
          name: 'prometheusrules.openshift.io',
          rules: [
            {
              apiGroups: ['monitoring.coreos.com'],
              apiVersions: ['v1'],
              operations: ['CREATE', 'UPDATE'],
              resources: ['prometheusrules'],
              scope: 'Namespaced',
            },
          ],
          clientConfig: {
            service: {
              namespace: 'openshift-monitoring',
              name: 'prometheus-operator',
              port: 8080,
              path: '/admission-prometheusrules/validate',
            },
          },
          admissionReviewVersions: ['v1'],
          sideEffects: 'None',
          timeoutSeconds: 5,
          failurePolicy: 'Ignore',
        },
      ],
    },
  }
