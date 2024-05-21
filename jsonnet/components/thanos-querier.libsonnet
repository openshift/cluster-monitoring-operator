local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';
local querier = import 'github.com/thanos-io/kube-thanos/jsonnet/kube-thanos/kube-thanos-query.libsonnet';

function(params)
  local cfg = params;
  local tq = querier(cfg);
  tq {
    mixin:: (import 'github.com/thanos-io/thanos/mixin/alerts/query.libsonnet') {
      targetGroups: {
        namespace: cfg.namespace,
      },
      query+:: {
        selector: 'job="thanos-querier"',
      },
    },

    prometheusRule: {
      apiVersion: 'monitoring.coreos.com/v1',
      kind: 'PrometheusRule',
      metadata: {
        name: 'thanos-querier',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
      },
      spec: $.mixin.prometheusAlerts,
    },

    trustedCaBundle: generateCertInjection.trustedCNOCaBundleCM(cfg.namespace, 'thanos-querier-trusted-ca-bundle'),

    route: {
      apiVersion: 'v1',
      kind: 'Route',
      metadata: {
        name: 'thanos-querier',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
      },
      spec: {
        path: '/api',
        to: {
          kind: 'Service',
          name: 'thanos-querier',
        },
        port: {
          targetPort: 'web',
        },
        tls: {
          termination: 'Reencrypt',
          insecureEdgeTerminationPolicy: 'Redirect',
        },
      },
    },

    clusterRole: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRole',
      metadata: {
        name: 'thanos-querier',
        labels: tq.config.commonLabels,
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
      ],
    },

    clusterRoleBinding: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRoleBinding',
      metadata: {
        name: 'thanos-querier',
        labels: tq.config.commonLabels,
      },
      roleRef: {
        apiGroup: 'rbac.authorization.k8s.io',
        kind: 'ClusterRole',
        name: 'thanos-querier',
      },
      subjects: [{
        kind: 'ServiceAccount',
        name: 'thanos-querier',
        namespace: cfg.namespace,
      }],
    },

    grpcTlsSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'thanos-querier-grpc-tls',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
      },
      type: 'Opaque',
      data: {},
    },

    // holds the secret which is used encrypt/decrypt cookies
    // issued by the oauth proxy.
    oauthCookieSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'thanos-querier-oauth-cookie',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
      },
      type: 'Opaque',
      data: {},
    },

    // holds the kube-rbac-proxy configuration as a secret.
    // It configures to template the request in flight
    // to extract a "namespace" query parameter
    // and perform a SubjectAccessReview
    // asserting if the request bearer token in flight has permissions
    // to access the pod.metrics.k8s.io API.
    // The asserted verb (PUT, GET, POST, etc.) is implied from the http request verb in flight.
    kubeRbacProxySecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'thanos-querier-kube-rbac-proxy',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
      },
      type: 'Opaque',
      data: {},
      stringData: {
        'config.yaml': std.manifestYamlDoc({
          authorization: {
            rewrites: {
              byQueryParameter: {
                name: 'namespace',
              },
            },
            resourceAttributes: {
              apiVersion: 'v1beta1',
              apiGroup: 'metrics.k8s.io',
              resource: 'pods',
              namespace: '{{ .Value }}',
            },
          },
        }),
      },
    },

    kubeRbacProxyMetricSecret: generateSecret.staticAuthSecret(cfg.namespace, cfg.commonLabels, 'thanos-querier-kube-rbac-proxy-metrics') + {
      metadata+: {
        labels: { 'app.kubernetes.io/name': 'thanos-query' },
      },
    },

    // Same as kubeRbacProxySecret but performs a SubjectAccessReview
    // asserting if the request bearer token in flight has permissions
    // to access the prometheusrules.monitoring.coreos.com API.
    kubeRbacProxyRulesSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'thanos-querier-kube-rbac-proxy-rules',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
      },
      type: 'Opaque',
      data: {},
      stringData: {
        'config.yaml': std.manifestYamlDoc({
          authorization: {
            rewrites: {
              byQueryParameter: {
                name: 'namespace',
              },
            },
            resourceAttributes: {
              apiGroup: 'monitoring.coreos.com',
              resource: 'prometheusrules',
              namespace: '{{ .Value }}',
            },
          },
        }),
      },
    },

    serviceAccount: {
      apiVersion: 'v1',
      kind: 'ServiceAccount',
      metadata: {
        name: 'thanos-querier',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
        annotations: {
          'serviceaccounts.openshift.io/oauth-redirectreference.thanos-querier': '{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"thanos-querier"}}',
        },
      },
    },

    service+: {
      apiVersion: 'v1',
      kind: 'Service',
      metadata+: {
        annotations: {
          'service.beta.openshift.io/serving-cert-secret-name': 'thanos-querier-tls',
        },
        labels: tq.config.commonLabels,
      },
      spec+: {
        ports: [
          {
            name: 'web',
            port: 9091,
            targetPort: 'web',
          },
          {
            name: 'tenancy',
            port: 9092,
            targetPort: 'tenancy',
          },
          {
            name: 'tenancy-rules',
            port: 9093,
            targetPort: 'tenancy-rules',
          },
          {
            name: 'metrics',
            port: 9094,
            targetPort: 'metrics',
          },
        ],
        type: 'ClusterIP',
      },
    },

    serviceMonitor+:
      {
        spec+: {
          endpoints: [
            {
              port: 'metrics',
              interval: '30s',
              scheme: 'https',
            },
          ],
        },
      },

    deployment+: {
      metadata+: {
        labels+: {
          'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
        },
      },
      spec+: {
        strategy+: {
          // Apply HA conventions
          rollingUpdate: {
            maxUnavailable: 1,
          },
        },
        template+: {
          metadata+: {
            labels+: {
              'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
            },
          },
          spec+: {
            // TODO(slashpai): remove once new kube-thanos is released which has this change
            nodeSelector: {
              'kubernetes.io/os': 'linux',
            },
            // TODO(dgrisonnet): remove once the upstream anti-affinity addon
            // can be extended.
            affinity+: {
              podAntiAffinity: {
                // Apply HA conventions
                requiredDuringSchedulingIgnoredDuringExecution: [
                  {
                    labelSelector: {
                      matchLabels: tq.config.podLabelSelector,
                    },
                    topologyKey: 'kubernetes.io/hostname',
                  },
                ],
              },
            },
            volumes+: [
              {
                name: 'secret-thanos-querier-tls',
                secret: {
                  secretName: 'thanos-querier-tls',
                },
              },
              {
                name: 'secret-thanos-querier-oauth-cookie',
                secret: {
                  secretName: 'thanos-querier-oauth-cookie',
                },
              },
              {
                name: 'secret-thanos-querier-kube-rbac-proxy',
                secret: {
                  secretName: 'thanos-querier-kube-rbac-proxy',
                },
              },
              {
                name: 'secret-thanos-querier-kube-rbac-proxy-rules',
                secret: {
                  secretName: 'thanos-querier-kube-rbac-proxy-rules',
                },
              },
              {
                name: 'secret-' + $.kubeRbacProxyMetricSecret.metadata.name,
                secret: {
                  secretName: $.kubeRbacProxyMetricSecret.metadata.name,
                },
              },
              {
                name: 'metrics-client-ca',
                configMap: {
                  name: 'metrics-client-ca',
                },
              },
            ],
            serviceAccountName: 'thanos-querier',
            priorityClassName: 'system-cluster-critical',
            securityContext: {
              runAsNonRoot: true,
              seccompProfile: {
                type: 'RuntimeDefault',
              },
            },
            containers: [
              super.containers[0] {
                livenessProbe:: {},
                readinessProbe:: {},
                args: std.map(
                  function(a)
                    if std.startsWith(a, '--grpc-address=') then '--grpc-address=127.0.0.1:10901'
                    else if std.startsWith(a, '--http-address=') then '--http-address=127.0.0.1:9090'
                    else a,
                  std.filter(function(a) !std.startsWith(a, '--log.level='), super.args)
                ) + [
                  '--store.sd-dns-resolver=miekgdns',
                  '--grpc-client-tls-secure',
                  '--grpc-client-tls-cert=/etc/tls/grpc/client.crt',
                  '--grpc-client-tls-key=/etc/tls/grpc/client.key',
                  '--grpc-client-tls-ca=/etc/tls/grpc/ca.crt',
                  '--grpc-client-server-name=prometheus-grpc',
                  '--rule=dnssrv+_grpc._tcp.prometheus-operated.openshift-monitoring.svc.cluster.local',
                  '--target=dnssrv+_grpc._tcp.prometheus-operated.openshift-monitoring.svc.cluster.local',
                ],
                resources: {
                  requests: {
                    memory: '12Mi',
                    cpu: '10m',
                  },
                },
                ports: [
                  {
                    containerPort: 9090,
                    name: 'http',
                  },
                ],
                volumeMounts+: [
                  {
                    mountPath: '/etc/tls/grpc',
                    name: 'secret-grpc-tls',
                  },
                ],
              },
              {
                name: 'oauth-proxy',
                image: 'quay.io/openshift/oauth-proxy:latest',  //FIXME(paulfantom)
                resources: {
                  requests: {
                    memory: '20Mi',
                    cpu: '1m',
                  },
                },
                ports: [{
                  containerPort: 9091,
                  name: 'web',
                }],
                env: [
                  { name: 'HTTP_PROXY', value: '' },
                  { name: 'HTTPS_PROXY', value: '' },
                  { name: 'NO_PROXY', value: '' },
                ],
                livenessProbe: {
                  httpGet: {
                    path: '/-/healthy',
                    port: 9091,
                    scheme: 'HTTPS',
                  },
                  initialDelaySeconds: 5,
                  periodSeconds: 30,
                  failureThreshold: 4,
                },
                readinessProbe: {
                  httpGet: {
                    path: '/-/ready',
                    port: 9091,
                    scheme: 'HTTPS',
                  },
                  initialDelaySeconds: 5,
                  periodSeconds: 5,
                  failureThreshold: 20,
                },
                args: [
                  '-provider=openshift',
                  '-https-address=:9091',
                  '-http-address=',
                  '-email-domain=*',
                  '-upstream=http://localhost:9090',
                  '-openshift-service-account=thanos-querier',
                  '-openshift-sar={"resource": "namespaces", "verb": "get"}',
                  '-openshift-delegate-urls={"/": {"resource": "namespaces", "verb": "get"}}',
                  '-tls-cert=/etc/tls/private/tls.crt',
                  '-tls-key=/etc/tls/private/tls.key',
                  '-client-secret-file=/var/run/secrets/kubernetes.io/serviceaccount/token',
                  '-cookie-secret-file=/etc/proxy/secrets/session_secret',
                  '-openshift-ca=/etc/pki/tls/cert.pem',
                  '-openshift-ca=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
                  '-bypass-auth-for=^/-/(healthy|ready)$',
                ],
                terminationMessagePolicy: 'FallbackToLogsOnError',
                volumeMounts: [
                  {
                    mountPath: '/etc/tls/private',
                    name: 'secret-thanos-querier-tls',
                  },
                  {
                    mountPath: '/etc/proxy/secrets',
                    name: 'secret-thanos-querier-oauth-cookie',
                  },
                ],
                securityContext: {
                  allowPrivilegeEscalation: false,
                  capabilities: {
                    drop: ['ALL'],
                  },
                },
              },
              {
                name: 'kube-rbac-proxy',
                image: cfg.kubeRbacProxyImage,
                resources: {
                  requests: {
                    memory: '15Mi',
                    cpu: '1m',
                  },
                },
                ports: [
                  {
                    containerPort: 9092,
                    name: 'tenancy',
                  },
                ],
                args: [
                  '--secure-listen-address=0.0.0.0:9092',
                  '--upstream=http://127.0.0.1:9095',
                  '--config-file=/etc/kube-rbac-proxy/config.yaml',
                  '--tls-cert-file=/etc/tls/private/tls.crt',
                  '--tls-private-key-file=/etc/tls/private/tls.key',
                  '--tls-cipher-suites=' + cfg.tlsCipherSuites,
                  '--logtostderr=true',
                  '--allow-paths=' + std.join(',', [
                    '/api/v1/query',
                    '/api/v1/query_range',
                    '/api/v1/labels',
                    '/api/v1/label/*/values',
                    '/api/v1/series',
                  ]),
                ],
                terminationMessagePolicy: 'FallbackToLogsOnError',
                volumeMounts: [
                  {
                    mountPath: '/etc/tls/private',
                    name: 'secret-thanos-querier-tls',
                  },
                  {
                    mountPath: '/etc/kube-rbac-proxy',
                    name: 'secret-' + $.kubeRbacProxySecret.metadata.name,
                  },
                ],
                securityContext: {
                  allowPrivilegeEscalation: false,
                  capabilities: {
                    drop: ['ALL'],
                  },
                },
              },
              {
                name: 'prom-label-proxy',
                image: cfg.promLabelProxyImage,
                args: [
                  '--insecure-listen-address=127.0.0.1:9095',
                  '--upstream=http://127.0.0.1:9090',
                  '--label=namespace',
                  '--enable-label-apis',
                  '--error-on-replace',
                ],
                resources: {
                  requests: {
                    memory: '15Mi',
                    cpu: '1m',
                  },
                },
                securityContext: {
                  allowPrivilegeEscalation: false,
                  capabilities: {
                    drop: ['ALL'],
                  },
                },
                terminationMessagePolicy: 'FallbackToLogsOnError',
              },
              {
                name: 'kube-rbac-proxy-rules',
                image: cfg.kubeRbacProxyImage,
                resources: {
                  requests: {
                    memory: '15Mi',
                    cpu: '1m',
                  },
                },
                ports: [
                  {
                    containerPort: 9093,
                    name: 'tenancy-rules',
                  },
                ],
                args: [
                  '--secure-listen-address=0.0.0.0:9093',
                  '--upstream=http://127.0.0.1:9095',
                  '--config-file=/etc/kube-rbac-proxy/config.yaml',
                  '--tls-cert-file=/etc/tls/private/tls.crt',
                  '--tls-private-key-file=/etc/tls/private/tls.key',
                  '--tls-cipher-suites=' + cfg.tlsCipherSuites,
                  '--logtostderr=true',
                  '--allow-paths=/api/v1/rules',
                ],
                terminationMessagePolicy: 'FallbackToLogsOnError',
                volumeMounts: [
                  {
                    mountPath: '/etc/tls/private',
                    name: 'secret-thanos-querier-tls',
                  },
                  {
                    mountPath: '/etc/kube-rbac-proxy',
                    name: 'secret-' + $.kubeRbacProxyRulesSecret.metadata.name,
                  },
                ],
                securityContext: {
                  allowPrivilegeEscalation: false,
                  capabilities: {
                    drop: ['ALL'],
                  },
                },
              },
              {
                // TODO: merge this metric proxy with tenancy proxy when the issue below is fixed:
                // https://github.com/brancz/kube-rbac-proxy/issues/146
                name: 'kube-rbac-proxy-metrics',
                image: cfg.kubeRbacProxyImage,
                resources: {
                  requests: {
                    memory: '15Mi',
                    cpu: '1m',
                  },
                },
                ports: [
                  {
                    containerPort: 9094,
                    name: 'metrics',
                  },
                ],
                args: [
                  '--secure-listen-address=0.0.0.0:9094',
                  '--upstream=http://127.0.0.1:9090',
                  '--config-file=/etc/kube-rbac-proxy/config.yaml',
                  '--tls-cert-file=/etc/tls/private/tls.crt',
                  '--tls-private-key-file=/etc/tls/private/tls.key',
                  '--tls-cipher-suites=' + cfg.tlsCipherSuites,
                  '--client-ca-file=/etc/tls/client/client-ca.crt',
                  '--logtostderr=true',
                  '--allow-paths=/metrics',
                ],
                terminationMessagePolicy: 'FallbackToLogsOnError',
                volumeMounts: [
                  {
                    mountPath: '/etc/tls/private',
                    name: 'secret-thanos-querier-tls',
                  },
                  {
                    mountPath: '/etc/kube-rbac-proxy',
                    name: 'secret-' + $.kubeRbacProxyMetricSecret.metadata.name,
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
        name: 'thanos-querier-pdb',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
      },
      spec: {
        minAvailable: 1,
        selector: {
          matchLabels: tq.config.podLabelSelector,
        },

      },
    },
  }
