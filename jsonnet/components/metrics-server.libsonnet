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
  clusterRoleAggregatedMetricsReader: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRole',
    metadata: {
      labels: {
        'app.kubernetes.io/name': 'aggregated-metrics-reader',
        'app.kubernetes.io/component': 'metrics-server',
        'rbac.authorization.k8s.io/aggregate-to-admin': 'true',
        'rbac.authorization.k8s.io/aggregate-to-edit': 'true',
        'rbac.authorization.k8s.io/aggregate-to-view': 'true',
      } + cfg.commonLabels,
      name: 'system:aggregated-metrics-reader',
    },
    rules: [
      {
        apiGroups: ['metrics.k8s.io'],
        resources: ['pods', 'nodes'],
        verbs: ['get', 'list', 'watch'],
      },
    ],
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
      },
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
        },
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
              args: [
                '--secure-port=10250',
                '--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname',
                '--kubelet-use-node-status-port',
                '--metric-resolution=15s',
                '--kubelet-certificate-authority=/etc/tls/kubelet-serving-ca-bundle/ca-bundle.crt',
                '--kubelet-client-certificate=/etc/tls/metrics-client-certs/tls.crt',
                '--kubelet-client-key=/etc/tls/metrics-client-certs/tls.key',
                '--tls-cert-file=/etc/tls/private/tls.crt',
                '--tls-private-key-file=/etc/tls/private/tls.key',
                '--tls-cipher-suites=' + cfg.tlsCipherSuites,
              ],
              image: 'registry.k8s.io/metrics-server/metrics-server:v0.6.3',
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
                  cpu: '100m',
                  memory: '200Mi',
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
                  mountPath: '/etc/tls/metrics-client-certs',
                  name: 'secret-metrics-client-certs',
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
              name: 'secret-metrics-client-certs',
              secret: {
                secretName: 'metrics-client-certs',
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
        },
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
