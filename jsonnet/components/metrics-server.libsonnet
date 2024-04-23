local withDescription = (import '../utils/add-annotations.libsonnet').withDescription;

function(params) {
  local cfg = params,

  serviceAccount: {
    apiVersion: 'v1',
    kind: 'ServiceAccount',
    metadata: {
      labels: {
        'app.kubernetes.io/name': 'metrics-server',
        'app.kubernetes.io/component': 'metrics-server',
      } + cfg.commonLabels,
      name: 'metrics-server',
      namespace: cfg.namespace,
    },
  },
  clusterRole: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRole',
    metadata: {
      labels: {
        'app.kubernetes.io/name': 'metrics-server',
        'app.kubernetes.io/component': 'metrics-server',
      } + cfg.commonLabels,
      name: 'system:metrics-server',
    },
    rules: [
      {
        apiGroups: [''],
        resources: ['nodes/metrics'],
        verbs: ['get'],
      },
      {
        apiGroups: [''],
        resources: ['pods', 'nodes'],
        verbs: ['get', 'list', 'watch'],
      },
    ],
  },
  roleBindingAuthReader: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'RoleBinding',
    metadata: {
      labels: {
        'app.kubernetes.io/name': 'metrics-server-auth-reader',
        'app.kubernetes.io/component': 'metrics-server',
      } + cfg.commonLabels,
      name: 'metrics-server-auth-reader',
      namespace: 'kube-system',
    },
    roleRef: {
      apiGroup: 'rbac.authorization.k8s.io',
      kind: 'Role',
      name: 'extension-apiserver-authentication-reader',
    },
    subjects: [
      {
        kind: 'ServiceAccount',
        name: 'metrics-server',
        namespace: cfg.namespace,
      },
    ],
  },
  clusterRoleBindingAuthDelegator: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRoleBinding',
    metadata: {
      labels: {
        'app.kubernetes.io/name': 'auth-delegator',
        'app.kubernetes.io/component': 'metrics-server',
      } + cfg.commonLabels,
      name: 'metrics-server:system:auth-delegator',
    },
    roleRef: {
      apiGroup: 'rbac.authorization.k8s.io',
      kind: 'ClusterRole',
      name: 'system:auth-delegator',
    },
    subjects: [
      {
        kind: 'ServiceAccount',
        name: 'metrics-server',
        namespace: cfg.namespace,
      },
    ],
  },
  clusterRoleBinding: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRoleBinding',
    metadata: {
      labels: {
        'app.kubernetes.io/name': 'metrics-server',
      } + cfg.commonLabels,
      name: 'system:metrics-server',
    },
    roleRef: {
      apiGroup: 'rbac.authorization.k8s.io',
      kind: 'ClusterRole',
      name: 'system:metrics-server',
    },
    subjects: [
      {
        kind: 'ServiceAccount',
        name: 'metrics-server',
        namespace: cfg.namespace,
      },
    ],
  },

  service: {
    apiVersion: 'v1',
    kind: 'Service',
    metadata: {
      labels: {
        'app.kubernetes.io/name': 'metrics-server',
        'app.kubernetes.io/component': 'metrics-server',
      } + cfg.commonLabels,
      annotations: {
        'service.beta.openshift.io/serving-cert-secret-name': 'metrics-server-tls',
      } + withDescription('Expose the metrics-server web server on port %d. This port is for internal use, and no other usage is guaranteed.' % $.service.spec.ports[0].port),
      name: 'metrics-server',
      namespace: cfg.namespace,
    },
    spec: {
      ports: [
        {
          name: 'https',
          port: 443,
          protocol: 'TCP',
          targetPort: 'https',
        },
      ],
      selector: {
        'app.kubernetes.io/name': 'metrics-server',
      } + cfg.commonLabels,
    },
  },

  deployment: {
    apiVersion: 'apps/v1',
    kind: 'Deployment',
    metadata: {
      labels: {
        'app.kubernetes.io/name': 'metrics-server',
        'app.kubernetes.io/component': 'metrics-server',
      } + cfg.commonLabels,
      name: 'metrics-server',
      namespace: cfg.namespace,
    },
    spec: {
      replicas: 2,
      selector: {
        matchLabels: {
          'app.kubernetes.io/name': 'metrics-server',
          'app.kubernetes.io/component': 'metrics-server',
        } + cfg.commonLabels,
      },
      strategy: {
        rollingUpdate: {
          maxUnavailable: 1,
        },
      },
      template: {
        metadata: {
          labels: {
            'app.kubernetes.io/name': 'metrics-server',
            'app.kubernetes.io/component': 'metrics-server',
          } + cfg.commonLabels,
        },
        spec: {
          affinity: {
            podAntiAffinity: {
              requiredDuringSchedulingIgnoredDuringExecution: [
                {
                  labelSelector: {
                    matchLabels: {
                      'app.kubernetes.io/name': 'metrics-server',
                      'app.kubernetes.io/component': 'metrics-server',
                    } + cfg.commonLabels,
                  },
                  namespaces: [cfg.namespace],
                  topologyKey: 'kubernetes.io/hostname',
                },
              ],
            },
          },
          containers: [
            {
              image: cfg.image,
              args: [
                '--secure-port=10250',
                '--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname',
                '--kubelet-use-node-status-port',
                '--metric-resolution=15s',
                '--kubelet-certificate-authority=/etc/tls/kubelet-serving-ca-bundle/ca-bundle.crt',
                '--kubelet-client-certificate=/etc/tls/metrics-server-client-certs/tls.crt',
                '--kubelet-client-key=/etc/tls/metrics-server-client-certs/tls.key',
                '--tls-cert-file=/etc/tls/private/tls.crt',
                '--tls-private-key-file=/etc/tls/private/tls.key',
                '--tls-cipher-suites=' + cfg.tlsCipherSuites,
              ],
              imagePullPolicy: 'IfNotPresent',
              livenessProbe: {
                failureThreshold: 3,
                httpGet: {
                  path: '/livez',
                  port: 'https',
                  scheme: 'HTTPS',
                },
                periodSeconds: 10,
              },
              name: 'metrics-server',
              ports: [
                {
                  containerPort: 10250,
                  name: 'https',
                  protocol: 'TCP',
                },
              ],
              // metrics-server waits for 2 scrapes to report ready.
              // The first one happens during boostrap and the second one after 15s (kubelet scrape interval)
              // kubelet scrape interval is specified in metrics-server flag `--metric-resolution=15s`
              readinessProbe: {
                failureThreshold: 3,
                httpGet: {
                  path: '/readyz',
                  port: 'https',
                  scheme: 'HTTPS',
                },
                initialDelaySeconds: 20,
                periodSeconds: 10,
              },
              resources: {
                requests: {
                  cpu: '1m',
                  memory: '40Mi',
                },
              },
              securityContext: {
                allowPrivilegeEscalation: false,
                readOnlyRootFilesystem: true,
                runAsNonRoot: true,
              },
              volumeMounts: [
                {
                  mountPath: '/etc/tls/private',
                  name: 'secret-metrics-server-tls',
                },
                {
                  mountPath: '/etc/tls/metrics-server-client-certs',
                  name: 'secret-metrics-server-client-certs',
                },
                {
                  mountPath: '/etc/tls/kubelet-serving-ca-bundle',
                  name: 'configmap-kubelet-serving-ca-bundle',
                },
              ],
            },
          ],
          nodeSelector: {
            'kubernetes.io/os': 'linux',
          },
          priorityClassName: 'system-cluster-critical',
          serviceAccountName: 'metrics-server',
          volumes: [
            {
              name: 'secret-metrics-server-client-certs',
              secret: {
                secretName: 'metrics-server-client-certs',
              },
            },
            {
              name: 'secret-metrics-server-tls',
              secret: {
                secretName: 'metrics-server-tls',
              },
            },
            {
              configMap: {
                name: 'kubelet-serving-ca-bundle',
              },
              name: 'configmap-kubelet-serving-ca-bundle',
            },
          ],
        },
      },
    },
  },
  podDisruptionBudget: {
    apiVersion: 'policy/v1',
    kind: 'PodDisruptionBudget',
    metadata: {
      labels: {
        'app.kubernetes.io/name': 'metrics-server',
        'app.kubernetes.io/component': 'metrics-server',
      } + cfg.commonLabels,
      name: 'metrics-server',
      namespace: cfg.namespace,
    },
    spec: {
      minAvailable: 1,
      selector: {
        matchLabels: {
          'app.kubernetes.io/name': 'metrics-server',
          'app.kubernetes.io/component': 'metrics-server',
        } + cfg.commonLabels,
      },
    },
  },
  apiService: {
    apiVersion: 'apiregistration.k8s.io/v1',
    kind: 'APIService',
    metadata: {
      name: 'v1beta1.metrics.k8s.io',
      labels: {
        'app.kubernetes.io/name': 'metrics-server',
        'app.kubernetes.io/component': 'metrics-server',
      } + cfg.commonLabels,
      annotations+: {
        'service.beta.openshift.io/inject-cabundle': 'true',
      },
    },
    spec: {
      service: {
        name: $.service.metadata.name,
        namespace: cfg.namespace,
        port: 443,
      },
      group: 'metrics.k8s.io',
      version: 'v1beta1',
      insecureSkipTLSVerify: false,
      groupPriorityMinimum: 100,
      versionPriority: 100,
    },
  },
  serviceMonitor: {
    apiVersion: 'monitoring.coreos.com/v1',
    kind: 'ServiceMonitor',
    metadata: {
      labels: {
        'app.kubernetes.io/name': 'metrics-server',
        'app.kubernetes.io/component': 'metrics-server',
      } + cfg.commonLabels,
      name: 'metrics-server',
      namespace: cfg.namespace,
    },
    spec: {
      endpoints: [
        {
          port: 'https',
          scheme: 'https',
        },
      ],
      selector: {
        matchLabels: {
          'app.kubernetes.io/name': 'metrics-server',
          'app.kubernetes.io/component': 'metrics-server',
        } + cfg.commonLabels,
      },
    },
  },
}
