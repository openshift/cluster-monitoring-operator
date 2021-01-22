local tlsVolumeName = 'prometheus-operator-user-workload-tls';

{
  prometheusOperatorUserWorkload:: $.prometheusOperator {
    namespace:: $._config.namespaceUserWorkload,

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

    deployment+: {
      spec+: {
        template+: {
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
                        '--deny-namespaces=' + $._config.namespace,
                        '--prometheus-instance-namespaces=' + $._config.namespaceUserWorkload,
                        '--alertmanager-instance-namespaces=' + $._config.namespaceUserWorkload,
                        '--thanos-ruler-instance-namespaces=' + $._config.namespaceUserWorkload,
                        '--config-reloader-cpu=0',
                        '--config-reloader-memory=0',
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
                      ],
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                      volumeMounts: [{
                        mountPath: '/etc/tls/private',
                        name: tlsVolumeName,
                        readOnly: false,
                      }],
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
            volumes+: [{
              name: tlsVolumeName,
              secret: {
                secretName: 'prometheus-operator-user-workload-tls',
              },
            }],
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
  },
}
