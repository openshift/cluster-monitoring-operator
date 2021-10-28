local generateSecret = import '../utils/generate-secret.libsonnet';
local grafana = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/grafana.libsonnet';

local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';

function(params)
  local cfg = params;

  // List of dashboards which should be shown in OCP developer perspective.
  local odcDashboards = [
    'grafana-dashboard-k8s-resources-namespace',
    'grafana-dashboard-k8s-resources-workloads-namespace',
    'grafana-dashboard-k8s-resources-pod',
    'grafana-dashboard-k8s-resources-workload',
  ];

  grafana(cfg) {

    consoleDashboardDefinitions: {
      apiVersion: 'v1',
      kind: 'ConfigMapList',
      items: std.map(
        function(d)
          d {
            metadata+: {
              namespace: 'openshift-config-managed',
              labels+: {
                'console.openshift.io/dashboard': 'true',
              } + if std.count(odcDashboards, d.metadata.name) > 0 then {
                'console.openshift.io/odc-dashboard': 'true',
              } else {},
            },
          },
        $.dashboardDefinitions.items,
      ),
    },

    trustedCaBundle: generateCertInjection.trustedCNOCaBundleCM(cfg.namespace, 'grafana-trusted-ca-bundle'),

    // OpenShift route to access the Grafana UI.
    route: {
      apiVersion: 'v1',
      kind: 'Route',
      metadata: {
        name: 'grafana',
        namespace: cfg.namespace,
      },
      spec: {
        to: {
          kind: 'Service',
          name: 'grafana',
        },
        port: {
          targetPort: 'https',
        },
        tls: {
          termination: 'Reencrypt',
          insecureEdgeTerminationPolicy: 'Redirect',
        },
      },
    },

    serviceMonitor+:
      {
        spec+: {
          endpoints: [
            {
              interval: '30s',
              port: 'metrics',
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

    // The ServiceAccount needs this annotation, to signify the identity
    // provider, that when a users it doing the oauth flow through the oauth
    // proxy, that it should redirect to the grafana route on
    // successful authentication.
    serviceAccount+: {
      metadata+: {
        annotations+: {
          'serviceaccounts.openshift.io/oauth-redirectreference.grafana': '{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"grafana"}}',
        },
      },
    },

    // Adding the serving certs annotation causes the serving certs controller
    // to generate a valid and signed serving certificate and put it in the
    // specified secret.
    //
    // The ClusterIP is explicitly set, as it signifies the
    // cluster-monitoring-operator, that when reconciling this service the
    // cluster IP needs to be retained.
    service+: {
      metadata+: {
        annotations: {
          'service.beta.openshift.io/serving-cert-secret-name': 'grafana-tls',
        },
      },
      spec+: {
        ports: [
          {
            name: 'https',
            port: 3000,
            targetPort: 'https',
          },
          {
            name: 'metrics',
            port: 3002,
            targetPort: 'metrics',
          },

        ],
        type: 'ClusterIP',
      },
    },

    // The proxy secret is there to encrypt session created by the oauth proxy.

    proxySecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'grafana-proxy',
        namespace: cfg.namespace,
        labels: { 'app.kubernetes.io/name': 'grafana' },
      },
      type: 'Opaque',
      data: {},
    },

    kubeRbacProxyMetricSecret: generateSecret.staticAuthSecret(cfg.namespace, cfg.commonLabels, 'grafana-kube-rbac-proxy-metric') + {
      metadata+: {
        labels: { 'app.kubernetes.io/name': 'grafana' },
      },
    },

    // In order for the oauth proxy to perform a TokenReview and
    // SubjectAccessReview for authN and authZ the Grafana ServiceAccount
    // requires the `create` action on both of these.

    clusterRole: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRole',
      metadata: {
        name: 'grafana',
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
        name: 'grafana',
      },
      roleRef: {
        apiGroup: 'rbac.authorization.k8s.io',
        kind: 'ClusterRole',
        name: 'grafana',
      },
      subjects: [{
        kind: 'ServiceAccount',
        name: 'grafana',
        namespace: cfg.namespace,
      }],
    },

    // These patches inject the oauth proxy as a sidecar and configures it with
    // TLS.

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
            containers: [
              super.containers[0] {
                args+: [
                  '-config=/etc/grafana/grafana.ini',
                ],
                ports: [{
                  name: 'http',
                  containerPort: 3001,
                }],
                readinessProbe:: null,
                resources+: {
                  requests+: {
                    cpu: '4m',
                    memory: '64Mi',
                  },
                },
              },
              {
                args: [
                  '-provider=openshift',
                  '-https-address=:3000',
                  '-http-address=',
                  '-email-domain=*',
                  '-upstream=http://localhost:3001',
                  '-openshift-sar={"resource": "namespaces", "verb": "get"}',
                  '-openshift-delegate-urls={"/": {"resource": "namespaces", "verb": "get"}}',
                  '-tls-cert=/etc/tls/private/tls.crt',
                  '-tls-key=/etc/tls/private/tls.key',
                  '-client-secret-file=/var/run/secrets/kubernetes.io/serviceaccount/token',
                  '-cookie-secret-file=/etc/proxy/secrets/session_secret',
                  '-openshift-service-account=grafana',
                  '-openshift-ca=/etc/pki/tls/cert.pem',
                  '-openshift-ca=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
                ],
                env: [
                  { name: 'HTTP_PROXY', value: '' },
                  { name: 'HTTPS_PROXY', value: '' },
                  { name: 'NO_PROXY', value: '' },
                ],
                image: 'quay.io/openshift/oauth-proxy:latest',  //FIXME(paulfantom)
                name: 'grafana-proxy',
                ports: [{
                  containerPort: 3000,
                  name: 'https',
                }],
                readinessProbe: {
                  httpGet: {
                    path: '/oauth/healthz',
                    port: 'https',
                    scheme: 'HTTPS',
                  },
                },
                resources: {
                  requests: { cpu: '1m', memory: '20Mi' },
                },
                volumeMounts: [
                  {
                    mountPath: '/etc/tls/private',
                    name: 'secret-grafana-tls',
                    readOnly: false,
                  },
                  {
                    mountPath: '/etc/proxy/secrets',
                    name: 'secret-grafana-proxy',
                    readOnly: false,
                  },
                ],
              },
              {
                // This kube-rbac-proxy sidecar is responsible for serving the /metrics endpoint and requires client TLS certificates for authentication.
                // We can't use oauth-proxy for this because it only supports bearer token authentication.
                name: 'kube-rbac-proxy-metrics',
                image: cfg.kubeRbacProxyImage,
                resources: {
                  requests: {
                    cpu: '1m',
                    memory: '15Mi',
                  },
                },
                ports: [
                  {
                    containerPort: 3002,
                    name: 'metrics',
                  },
                ],
                args: [
                  '--secure-listen-address=0.0.0.0:3002',
                  '--upstream=http://127.0.0.1:3001',
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
                    mountPath: '/etc/kube-rbac-proxy',
                    name: 'secret-' + $.kubeRbacProxyMetricSecret.metadata.name,
                    readOnly: true,
                  },
                  {
                    mountPath: '/etc/tls/private',
                    name: 'secret-grafana-tls',
                    readOnly: true,
                  },
                  {
                    mountPath: '/etc/tls/client',
                    name: 'metrics-client-ca',
                    readOnly: true,
                  },
                ],
              },
            ],
            volumes+: [
              {
                name: 'secret-grafana-tls',
                secret: {
                  secretName: 'grafana-tls',
                },
              },
              {
                name: 'secret-' + $.kubeRbacProxyMetricSecret.metadata.name,
                secret: {
                  secretName: $.kubeRbacProxyMetricSecret.metadata.name,
                },
              },
              {
                name: 'secret-grafana-proxy',
                secret: {
                  secretName: 'grafana-proxy',
                },
              },
              {
                name: 'metrics-client-ca',
                configMap: {
                  name: 'metrics-client-ca',
                },
              },
            ],
            securityContext: {},
            priorityClassName: 'system-cluster-critical',
          },
        },
      },
    },
  }
