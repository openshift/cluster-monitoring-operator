local tlsVolumeName = 'prometheus-operator-user-workload-tls';

local operator = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/prometheus-operator.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';

function(params)
  local cfg = params;
  operator(cfg) + {

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

    clusterRole+: {
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
    kubeRbacProxySecret: generateSecret.staticAuthSecret(cfg.namespace, cfg.commonLabels, 'prometheus-operator-uwm-kube-rbac-proxy-config'),
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
            securityContext: {},
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
                        '--prometheus-instance-namespaces=' + cfg.namespace,
                        '--alertmanager-instance-namespaces=' + cfg.namespace,
                        '--thanos-ruler-instance-namespaces=' + cfg.namespace,
                        '--config-reloader-cpu-limit=0',
                        '--config-reloader-memory-limit=0',
                      ],
                      securityContext: {},
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
                      ],
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                      volumeMounts: [
                        {
                          mountPath: '/etc/tls/private',
                          name: tlsVolumeName,
                          readOnly: false,
                        },
                        {
                          mountPath: '/etc/kube-rbac-policy',
                          name: 'prometheus-operator-uwm-kube-rbac-proxy-config',
                          readOnly: true,
                        },
                      ],
                      securityContext: {},
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
            bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            port: 'https',
            scheme: 'https',
            tlsConfig: {
              caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
              serverName: 'server-name-replaced-at-runtime',
            },
          },
        ],
      },
    },
  }
