local tlsVolumeName = 'prometheus-operator-user-workload-tls';

local operator = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/prometheus-operator.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';
local rbac = import '../utils/rbac.libsonnet';

function(params)
  local po = operator(params);

  po {

    mixin:: null,
    prometheusRule:: null,
    '0alertmanagerCustomResourceDefinition':: {},
    '0alertmanagerConfigCustomResourceDefinition':: {},
    '0prometheusCustomResourceDefinition':: {},
    '0servicemonitorCustomResourceDefinition':: {},
    '0podmonitorCustomResourceDefinition':: {},
    '0prometheusruleCustomResourceDefinition':: {},
    '0thanosrulerCustomResourceDefinition':: {},
    '0probeCustomResourceDefinition':: {},
    '0prometheusagentCustomResourceDefinition':: {},
    '0scrapeconfigCustomResourceDefinition':: {},

    // See jsonnet/components/prometheus-operator.libsonnet
    clusterRole: rbac.removeRulesByResourcePrefix(
      rbac.removeRulesByResourcePrefix(
        po.clusterRole,
        'monitoring.coreos.com',
        'prometheusagents',
      ),
      'monitoring.coreos.com',
      'scrapeconfigs',
    ) + {
      metadata+: {
        name: 'prometheus-user-workload-operator',
      },
    },

    clusterRoleBinding+: {
      metadata+: {
        name: 'prometheus-user-workload-operator',
      },
      roleRef+: {
        name: 'prometheus-user-workload-operator',
      },
    },

    kubeRbacProxySecret: generateSecret.staticAuthSecret(params.namespace, params.commonLabels, 'prometheus-operator-uwm-kube-rbac-proxy-config'),

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
            tolerations: [
              {
                key: 'node-role.kubernetes.io/master',
                operator: 'Exists',
                effect: 'NoSchedule',
              },
            ],
            securityContext: {
              runAsNonRoot: true,
              seccompProfile: {
                type: 'RuntimeDefault',
              },
            },
            priorityClassName: 'openshift-user-critical',
            containers:
              std.map(
                function(c)
                  if c.name == 'prometheus-operator' then
                    c {
                      args: std.filter(
                        function(arg) !std.startsWith(arg, '--kubelet-service'),
                        super.args,
                      ) + [
                        '--prometheus-instance-namespaces=' + params.namespace,
                        '--alertmanager-instance-namespaces=' + params.namespace,
                        '--thanos-ruler-instance-namespaces=' + params.namespace,
                        '--config-reloader-cpu-limit=0',
                        '--config-reloader-memory-limit=0',
                        '--config-reloader-cpu-request=1m',
                        '--config-reloader-memory-request=10Mi',
                        '--web.listen-address=127.0.0.1:8080',
                      ],
                      ports: [],
                      resources: {
                        requests: {
                          memory: '17Mi',
                          cpu: '1m',
                        },
                      },
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                    }
                  else if c.name == 'kube-rbac-proxy' then
                    c {
                      args+: [
                        '--tls-cert-file=/etc/tls/private/tls.crt',
                        '--tls-private-key-file=/etc/tls/private/tls.key',
                        '--config-file=/etc/kube-rbac-policy/config.yaml',
                        '--client-ca-file=/etc/tls/client/client-ca.crt',
                      ],
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                      volumeMounts: [
                        {
                          mountPath: '/etc/tls/private',
                          name: tlsVolumeName,
                          readOnly: true,
                        },
                        {
                          mountPath: '/etc/kube-rbac-policy',
                          name: 'prometheus-operator-uwm-kube-rbac-proxy-config',
                          readOnly: true,
                        },
                        {
                          mountPath: '/etc/tls/client',
                          name: 'metrics-client-ca',
                          readOnly: true,
                        },
                      ],
                      securityContext: {
                        allowPrivilegeEscalation: false,
                        capabilities: {
                          drop: ['ALL'],
                        },
                      },
                      resources: {
                        requests: {
                          memory: '10Mi',
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
                  secretName: 'prometheus-operator-user-workload-tls',
                },
              },
              {
                name: 'prometheus-operator-uwm-kube-rbac-proxy-config',
                secret: {
                  secretName: 'prometheus-operator-uwm-kube-rbac-proxy-config',
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
          'service.beta.openshift.io/serving-cert-secret-name': 'prometheus-operator-user-workload-tls',
        },
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
  }
