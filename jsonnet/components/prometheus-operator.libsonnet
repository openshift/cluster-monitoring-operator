local tlsVolumeName = 'prometheus-operator-tls';
local certsCAVolumeName = 'operator-certs-ca-bundle';

local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';

local operator = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/prometheus-operator.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';

function(params)
  local cfg = params;
  operator(cfg) + {
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
                    c {
                      args+: [
                        '--prometheus-instance-namespaces=' + cfg.namespace,
                        '--thanos-ruler-instance-namespaces=' + cfg.namespace,
                        '--alertmanager-instance-namespaces=' + cfg.namespace,
                        '--config-reloader-cpu-limit=0',
                        '--config-reloader-memory-limit=0',
                        '--web.enable-tls=true',
                        '--web.tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305',
                        '--web.tls-min-version=VersionTLS12',
                      ],
                      securityContext: {},
                      resources: {
                        requests: {
                          memory: '150Mi',
                          cpu: '5m',
                        },
                      },
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                      volumeMounts+: [{
                        mountPath: '/etc/tls/private',
                        name: tlsVolumeName,
                        readOnly: false,
                      }],
                    }
                  else if c.name == 'kube-rbac-proxy' then
                    c {
                      args: [
                        '--logtostderr',
                        '--secure-listen-address=:8443',
                        '--tls-cipher-suites=' + cfg.tlsCipherSuites,
                        '--upstream=https://prometheus-operator.openshift-monitoring.svc:8080/',
                        '--tls-cert-file=/etc/tls/private/tls.crt',
                        '--tls-private-key-file=/etc/tls/private/tls.key',
                        '--client-ca-file=/etc/tls/client/client-ca.crt',
                        '--upstream-ca-file=/etc/configmaps/operator-cert-ca-bundle/service-ca.crt',
                        '--config-file=/etc/kube-rbac-policy/config.yaml',
                      ],
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                      volumeMounts: [
                        {
                          mountPath: '/etc/tls/private',
                          name: tlsVolumeName,
                          readOnly: false,
                        },
                        {
                          mountPath: '/etc/configmaps/operator-cert-ca-bundle',
                          name: certsCAVolumeName,
                          readOnly: false,
                        },
                        {
                          mountPath: '/etc/tls/client',
                          name: 'metrics-client-ca',
                          readOnly: false,
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
              generateCertInjection.SCOCaBundleVolume(certsCAVolumeName),
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
      spec+: {
        ports+: [{ name: 'web', port: 8080, targetPort: 8080 }],
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

    operatorCertsCaBundle: generateCertInjection.SCOCaBundleCM(cfg.namespace, certsCAVolumeName),

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
