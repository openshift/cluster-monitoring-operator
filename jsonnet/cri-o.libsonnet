local defaults = {
  local defaults = self,
  namespace: error 'must provide namespace',
  name: 'crio-metrics',
  proxyName: self.name + '-proxy',
  servingPort: 9538,
};

local crio = function(params) {
  local g = self,
  _config:: defaults + params,

  securityContextConstraints: {
    apiVersion: 'security.openshift.io/v1',
    kind: 'SecurityContextConstraints',
    metadata: {
      annotations: {
        'kubernetes.io/description': 'Used for CRI-O metrics',
      },
      name: g._config.name,
    },
    allowHostDirVolumePlugin: true,
    allowHostIPC: false,
    allowHostNetwork: true,
    allowHostPID: false,
    allowHostPorts: true,
    allowPrivilegeEscalation: false,
    allowPrivilegedContainer: false,
    readOnlyRootFilesystem: false,
    runAsUser: {
      type: 'RunAsAny',
    },
    seLinuxContext: {
      type: 'RunAsAny',
    },
    users: [
      'system:serviceaccount:' + g._config.namespace + ':' + g._config.name,
    ],
  },

  serviceAccount: {
    apiVersion: 'v1',
    kind: 'ServiceAccount',
    metadata: {
      name: g._config.name,
      namespace: g._config.namespace,
    },
  },

  clusterRole: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRole',
    metadata: {
      name: g._config.name,
    },
    rules: [
      {
        apiGroups: ['authentication.k8s.io'],
        resources: ['tokenreviews'],
        verbs: ['create'],
      },
      {
        apiGroups: ['authorization.k8s.io'],
        resources: ['subjectaccessreviews'],
        verbs: ['create'],
      },
      {
        apiGroups: ['security.openshift.io'],
        resources: ['securitycontextconstraints'],
        resourceNames: [g._config.name],
        verbs: ['use'],
      },
    ],
  },

  clusterRoleBinding: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRoleBinding',
    metadata: {
      name: g._config.name,
    },
    roleRef: {
      apiGroup: 'rbac.authorization.k8s.io',
      kind: 'ClusterRole',
      name: g._config.name,
    },
    subjects: [
      {
        kind: 'ServiceAccount',
        name: g._config.name,
        namespace: g._config.namespace,
      },
    ],
  },

  secret: {
    apiVersion: 'v1',
    kind: 'Secret',
    type: 'Opaque',
    metadata: {
      name: g._config.name,
      namespace: g._config.namespace,
    },
    data: {},
  },

  service: {
    apiVersion: 'v1',
    kind: 'Service',
    metadata: {
      name: g._config.name,
      namespace: g._config.namespace,
      labels: {
        name: g._config.name,
      },
    },
    spec: {
      clusterIP: 'None',
      ports: [{
        name: 'https',
        port: 443,
        targetPort: 'https',
      }],
      selector: {
        name: g._config.proxyName,
      },
    },
  },

  serviceMonitor: {
    apiVersion: 'monitoring.coreos.com/v1',
    kind: 'ServiceMonitor',
    metadata: {
      name: g._config.name,
      namespace: g._config.namespace,
    },
    spec: {
      endpoints: [{
        bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
        interval: '10s',
        path: '/metrics',
        port: 'https',
        scheme: 'https',
        tlsConfig: {
          serverName: g._config.name,
          ca: {
            secret: {
              key: g._config.name + '-server.crt',
              name: g._config.name,
            },
          },
        },
      }],
      selector: {
        matchLabels: {
          name: g._config.name,
        },
      },
    },
  },

  daemonset: {
    apiVersion: 'apps/v1',
    kind: 'DaemonSet',
    metadata: {
      name: g._config.proxyName,
      namespace: g._config.namespace,
    },
    spec: {
      selector: {
        matchLabels: {
          name: g._config.proxyName,
        },
      },
      template: {
        metadata: {
          labels: {
            name: g._config.proxyName,
          },
        },
        spec: {
          hostNetwork: true,
          serviceAccountName: g._config.name,
          tolerations: [{
            effect: 'NoSchedule',
            key: 'node-role.kubernetes.io/master',
          }],
          containers: [
            {
              name: 'proxy',
              image: 'quay.io/brancz/kube-rbac-proxy:v0.9.0',
              args: [
                // TODO: use https if CRI-O supports it
                '--upstream=http://127.0.0.1:9537',
                '--secure-listen-address=0.0.0.0:' + g._config.servingPort,
                '--v=10',
                '--tls-cert-file=/tls/' + g._config.name + '-server.crt',
                '--tls-private-key-file=/tls/' + g._config.name + '-server.key',
              ],
              ports: [{
                name: 'https',
                containerPort: g._config.servingPort,
              }],
              volumeMounts: [{
                mountPath: '/tls',
                name: g._config.name,
              }],
            },
            {
              name: 'sidecar',
              image: 'registry.fedoraproject.org/fedora-minimal:34',
              args: [
                'bash',
                '-c',
                'while true; do echo "Copying certs" && cp /tls/* /crio && sleep 86400; done',
              ],
              volumeMounts: [
                {
                  name: g._config.name,
                  mountPath: '/tls',
                },
                {
                  name: 'etc-crio-certs',
                  mountPath: '/crio',
                },
              ],
            },
          ],
          volumes: [
            {
              name: g._config.name,
              secret: {
                secretName: g._config.name,
              },
            },
            {
              name: 'etc-crio-certs',
              hostPath: {
                path: '/etc/crio/certs',
                type: 'DirectoryOrCreate',
              },
            },
          ],
        },
      },
    },
  },

};

function(params)
  local cfg = params;
  crio(cfg) {}
