local tlsVolumeName = 'prometheus-operator-tls';

local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';
local operator = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/prometheus-operator.libsonnet';
local conversionWebhook = import 'github.com/prometheus-operator/prometheus-operator/jsonnet/prometheus-operator/conversion.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';
local rbac = import '../utils/rbac.libsonnet';
local withDescription = (import '../utils/add-annotations.libsonnet').withDescription;

function(params)
  local po = operator(params);

  po {
    '0alertmanagerConfigCustomResourceDefinition'+:
      // Add v1beta1 AlertmanagerConfig version.
      (import 'github.com/prometheus-operator/prometheus-operator/jsonnet/prometheus-operator/alertmanagerconfigs-v1beta1-crd.libsonnet') +
      // Enable conversion webhook.
      conversionWebhook(params.conversionWebhook),

    // The cluster monitoring operator doesn't need/support the PrometheusAgent and
    // ScrapeConfig CRDs so they need to be removed from the generated assets.
    '0prometheusagentCustomResourceDefinition':: {},
    '0scrapeconfigCustomResourceDefinition':: {},

    // For the same reason, the permissions on PrometheusAgent and ScrapeConfig resources should be removed.
    clusterRole: rbac.removeRulesByResourcePrefix(
      rbac.removeRulesByResourcePrefix(
        po.clusterRole,
        'monitoring.coreos.com',
        'prometheusagents',
      ),
      'monitoring.coreos.com',
      'scrapeconfigs',
    ),

    kubeRbacProxySecret: generateSecret.staticAuthSecret(params.namespace, params.commonLabels, 'prometheus-operator-kube-rbac-proxy-config'),
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
            annotations+: {
              'openshift.io/required-scc': 'restricted-v2',
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
                        '--prometheus-instance-namespaces=' + params.namespace,
                        '--thanos-ruler-instance-namespaces=' + params.namespace,
                        '--alertmanager-instance-namespaces=' + params.namespace,
                        '--config-reloader-cpu-limit=0',
                        '--config-reloader-memory-limit=0',
                        '--config-reloader-cpu-request=1m',
                        '--config-reloader-memory-request=10Mi',
                        '--web.listen-address=127.0.0.1:8080',
                        '--controller-id=openshift-monitoring/prometheus-operator',
                      ],
                      ports: [],
                      resources: {
                        requests: {
                          memory: '150Mi',
                          cpu: '5m',
                        },
                      },
                    }
                  else if c.name == 'kube-rbac-proxy' then
                    // TODO(simonpasquier): remove kube-rbac-proxy and
                    // configure the proper client CA + name in the prometheus
                    // operator container directly (once prometheus operator
                    // upstream supports name verification).
                    c {
                      args: [
                        '--secure-listen-address=:8443',
                        '--tls-cipher-suites=' + params.tlsCipherSuites,
                        '--upstream=http://localhost:8080/',
                        '--tls-cert-file=/etc/tls/private/tls.crt',
                        '--tls-private-key-file=/etc/tls/private/tls.key',
                        '--client-ca-file=/etc/tls/client/client-ca.crt',
                        '--config-file=/etc/kube-rbac-policy/config.yaml',
                      ],
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
        } + withDescription('Expose the `/metrics` endpoint on port %d. This port is for internal use, and no other usage is guaranteed.' % $.service.spec.ports[0].port),
      },
    },

    serviceMonitor+: {
      spec+: {
        endpoints: [
          {
            honorLabels: true,
            port: 'https',
            scheme: 'https',
          },
        ],
      },
    },
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
        name: 'prometheus-operator-admission-webhook-access',
        namespace: cfg.namespace,
      },
      spec: {
        podSelector: {
          matchLabels: {
            'app.kubernetes.io/name': 'prometheus-operator-admission-webhook',
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
