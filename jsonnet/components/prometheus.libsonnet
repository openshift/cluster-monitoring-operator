local metrics = import 'github.com/openshift/telemeter/jsonnet/telemeter/metrics.jsonnet';

local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';
local prometheus = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/prometheus.libsonnet';

function(params)
  local cfg = params;

  prometheus(cfg) + {
    trustedCaBundle: generateCertInjection.trustedCNOCaBundleCM(cfg.namespace, 'prometheus-trusted-ca-bundle'),

    grpcTlsSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'prometheus-k8s-grpc-tls',
        namespace: cfg.namespace,
        labels: { 'app.kubernetes.io/name': 'prometheus-k8s' },
      },
      type: 'Opaque',
      data: {},
    },

    // OpenShift route to access the Prometheus api.
    apiRoute: {
      apiVersion: 'v1',
      kind: 'Route',
      metadata: {
        name: 'prometheus-k8s',
        namespace: cfg.namespace,
      },
      spec: {
        to: {
          kind: 'Service',
          name: 'prometheus-k8s',
        },
        path: '/api',
        port: {
          targetPort: 'web',
        },
        tls: {
          termination: 'Reencrypt',
          insecureEdgeTerminationPolicy: 'Redirect',
        },
      },
    },

    // OpenShift route to access the Prometheus federate endpoint.
    federateRoute: {
      apiVersion: 'v1',
      kind: 'Route',
      metadata: {
        name: 'prometheus-k8s-federate',
        namespace: cfg.namespace,
      },
      spec: {
        to: {
          kind: 'Service',
          name: 'prometheus-k8s',
        },
        path: '/federate',
        port: {
          targetPort: 'web',
        },
        tls: {
          termination: 'Reencrypt',
          insecureEdgeTerminationPolicy: 'Redirect',
        },
      },
    },

    serviceAccount+: {
      // service account token is managed by the operator.
      automountServiceAccountToken: false,
    },

    // Adding the serving certs annotation causes the serving certs controller
    // to generate a valid and signed serving certificate and put it in the
    // specified secret.
    //
    // The ClusterIP is explicitly set, as it signifies the
    // cluster-monitoring-operator, that when reconciling this service the
    // cluster IP needs to be retained.
    //
    // The ports are overridden, as due to the port binding of the kube-rbac-proxy
    // the serving port is 9091 instead of the 9090 default.
    service+: {
      metadata+: {
        annotations: {
          'service.beta.openshift.io/serving-cert-secret-name': 'prometheus-k8s-tls',
        },
      },
      spec+: {
        ports: [
          {
            name: 'web',
            port: 9091,
            targetPort: 'web',
          },
          {
            name: 'metrics',
            port: 9092,
            targetPort: 'metrics',
          },
        ],
        type: 'ClusterIP',
      },
    },

    servingCertsCaBundle+: generateCertInjection.SCOCaBundleCM(cfg.namespace, 'serving-certs-ca-bundle'),

    // Even though this bundle will be frequently rotated by the CSR
    // controller, there is no need to add a ConfigMap reloader to
    // the Prometheus Pods because Prometheus automatically reloads
    // its cert pool every 5 seconds.
    // TODO(paulfantom): Should this be moved to control-plane?
    kubeletServingCaBundle+: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata+: {
        name: 'kubelet-serving-ca-bundle',
        namespace: cfg.namespace,
        annotations: {
          'openshift.io/owning-component': 'Monitoring',
        },
      },
      data: {},
    },

    // As Prometheus and Thanos are protected by the kube-rbac-proxy,
    // it requires the ability to create TokenReview and SubjectAccessReview requests.
    // The subresource prometheuses/api is used by the Thanos querier and Prometheus to
    // check a user's privilege to query the Prometheus API.
    // Additionally in order to authenticate with the Alertmanager it
    // requires `get` method on all `namespaces`, which is the
    // SubjectAccessReview required by the Alertmanager instances.
    clusterRole+: {
      rules+: [
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
          apiGroups: [''],
          resources: ['namespaces'],
          verbs: ['get'],
        },
        {
          // By default authenticated service accounts are assigned to the `restricted` SCC which implies MustRunAsRange.
          // This is problematic with statefulsets as UIDs (and file permissions) can change if SCCs are elevated.
          // Instead, this sets the `nonroot` SCC in conjunction with a static fsGroup and runAsUser security context below
          // to be immune against UID changes.
          apiGroups: ['security.openshift.io'],
          resources: ['securitycontextconstraints'],
          resourceNames: ['nonroot'],
          verbs: ['use'],
        },
        {
          // Access to the Prometheus / Thanos HTTP API through kube-rbac-proxy.
          // openshift/origin test using the service account "prometheus-k8s" to execute prometheus API calls.
          // This is required for the "prometheus-k8s" service account to be able to query the web port of
          // the thanos-querier service web port.
          apiGroups: ['monitoring.coreos.com'],
          resources: ['prometheuses/api'],
          resourceNames: ['k8s'],
          verbs: ['get', 'create', 'update'],
        },
      ],
    },

    alertmanagerRoleBinding: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'RoleBinding',
      metadata: {
        name: 'alertmanager-prometheus' + cfg.name,
        labels: cfg.commonLabels,
        namespace: 'openshift-monitoring',
      },
      roleRef: {
        apiGroup: 'rbac.authorization.k8s.io',
        kind: 'Role',
        name: 'monitoring-alertmanager-edit',
      },
      subjects: [{
        kind: 'ServiceAccount',
        name: 'prometheus-' + cfg.name,
        namespace: cfg.namespace,
      }],
    },

    kubeRbacProxySecret: generateSecret.staticAuthSecret(
      cfg.namespace,
      cfg.commonLabels,
      'kube-rbac-proxy',
      {
        authorization+: {
          static+: [
            {
              user: {
                name: 'system:serviceaccount:openshift-monitoring:prometheus-k8s',
              },
              verb: 'get',
              path: '/federate',
              resourceRequest: false,
            },
            {
              user: {
                name: 'system:serviceaccount:openshift-monitoring:telemeter-client',
              },
              verb: 'get',
              path: '/federate',
              resourceRequest: false,
            },
          ],
        },
      },
    ),

    // This is the KubeRBACProxy configuration for the web endpoint.
    // In previous version, anyone with a "get" access on "namespace" resource
    // can access the web endpoint. But KubeRBACProxy takes "get" verb as HTTP GET
    // method, while the web endpoint should accept both GET and POST method.
    // The sub resource prometheuses/api is used to implement this security setting.
    kubeRbacProxyWebSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'prometheus-k8s-kube-rbac-proxy-web',
        namespace: cfg.namespace,
        labels: cfg.commonLabels,
      },
      type: 'Opaque',
      stringData: {
        'config.yaml': std.manifestYamlDoc({
          authorization: {
            resourceAttributes: {
              apiGroup: 'monitoring.coreos.com',
              resource: 'prometheuses',
              subresource: 'api',
              namespace: 'openshift-monitoring',
              name: 'k8s',
            },
          },
        }),
      },
    },

    // Secret holding the token to authenticate against the Telemetry server when using native remote-write.
    telemetrySecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'telemetry-server',
        namespace: cfg.namespace,
        labels: { 'app.kubernetes.io/name': 'prometheus-k8s' },
      },
      type: 'Opaque',
      data: {},
    },

    // This changes the Prometheuses to be scraped with TLS, authN and
    // authZ, which are not present in kube-prometheus.

    serviceMonitor+: {
      spec+: {
        endpoints: [
          {
            port: 'metrics',
            interval: '30s',
            scheme: 'https',
            tlsConfig: {
              caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
              certFile: '/etc/prometheus/secrets/metrics-client-certs/tls.crt',
              keyFile: '/etc/prometheus/secrets/metrics-client-certs/tls.key',
            },
          },
        ],
      },
    },

    serviceThanosSidecar+: {
      metadata+: {
        annotations+: {
          'service.beta.openshift.io/serving-cert-secret-name': 'prometheus-k8s-thanos-sidecar-tls',
        },
      },
      spec+: {
        ports: [{
          name: 'thanos-proxy',
          port: 10902,
          targetPort: 'thanos-proxy',
        }],
      },
    },

    serviceMonitorThanosSidecar+: {
      spec+: {
        jobLabel:: null,
        endpoints: [
          {
            port: 'thanos-proxy',
            interval: '30s',
            scheme: 'https',
            tlsConfig: {
              caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
              certFile: '/etc/prometheus/secrets/metrics-client-certs/tls.crt',
              keyFile: '/etc/prometheus/secrets/metrics-client-certs/tls.key',
            },
          },
        ],
      },
    },

    // These patches inject the kube-rbac-proxy as a sidecar and configures it with
    // TLS. Additionally as the Alertmanager is protected with TLS, authN and
    // authZ it requires some additonal configuration.
    prometheus+: {
      spec+: {
        alerting+: {
          alertmanagers:
            std.map(
              function(a) a {
                scheme: 'https',
                tlsConfig: {
                  caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                  serverName: 'alertmanager-main',
                },
                bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
                apiVersion: 'v2',
              },
              super.alertmanagers,
            ),
        },
        resources: {
          requests: {
            memory: '1Gi',
            cpu: '70m',
          },
        },
        web: {
          httpConfig: {
            headers: {
              contentSecurityPolicy: "frame-ancestors 'none'",
            },
          },
        },
        securityContext: {
          fsGroup: 65534,
          runAsNonRoot: true,
          runAsUser: 65534,
        },
        secrets+: [
          'prometheus-k8s-tls',
          'prometheus-k8s-thanos-sidecar-tls',
          'kube-rbac-proxy',
          'prometheus-k8s-kube-rbac-proxy-web',
          'metrics-client-certs',
        ],
        externalURL: 'https://prometheus-k8s.openshift-monitoring.svc:9091',
        configMaps: ['serving-certs-ca-bundle', 'kubelet-serving-ca-bundle', 'metrics-client-ca'],
        probeNamespaceSelector: cfg.namespaceSelector,
        podMonitorNamespaceSelector: cfg.namespaceSelector,
        serviceMonitorSelector: {},
        serviceMonitorNamespaceSelector: cfg.namespaceSelector,
        ruleSelector: {},
        ruleNamespaceSelector: cfg.namespaceSelector,
        scrapeConfigSelector: null,
        scrapeConfigNamespaceSelector: null,
        listenLocal: true,
        priorityClassName: 'system-cluster-critical',
        additionalAlertRelabelConfigs: cfg.additionalRelabelConfigs,
        additionalArgs: [
          // This aligns any scrape timestamps <= 15ms to the a multiple of
          // the scrape interval. This optmizes tsdb compression.
          // 15ms was chosen for being a conservative value given our default
          // scrape interval of 30s. Even for half the default value we onlt
          // move scrape interval timestamps by <= 1% of their absolute
          // length.
          {
            name: 'scrape.timestamp-tolerance',
            value: '15ms',
          },
        ],
        containers: [
          {
            name: 'kube-rbac-proxy-web',
            image: cfg.kubeRbacProxyImage,
            resources: {
              requests: {
                memory: '15Mi',
                cpu: '1m',
              },
            },
            ports: [
              {
                containerPort: 9091,
                name: 'web',
              },
            ],
            args: [
              '--secure-listen-address=0.0.0.0:9091',
              '--upstream=http://127.0.0.1:9090',
              '--config-file=/etc/kube-rbac-proxy/config.yaml',
              '--tls-cert-file=/etc/tls/private/tls.crt',
              '--tls-private-key-file=/etc/tls/private/tls.key',
              '--client-ca-file=/etc/tls/client/client-ca.crt',
              '--tls-cipher-suites=' + cfg.tlsCipherSuites,
              /* no check for healthy and ready probes */
              '--ignore-paths=' + std.join(',', [
                '/-/healthy',
                '/-/ready',
              ]),
              // TODO: remove this after testing
              '-v=10',
            ],
            terminationMessagePolicy: 'FallbackToLogsOnError',
            volumeMounts: [
              {
                mountPath: '/etc/tls/private',
                name: 'secret-prometheus-k8s-tls',
              },
              {
                mountPath: '/etc/tls/client',
                name: 'configmap-metrics-client-ca',
                readOnly: true,
              },
              {
                mountPath: '/etc/kube-rbac-proxy',
                name: 'secret-' + $.kubeRbacProxyWebSecret.metadata.name,
              },
            ],
            securityContext: {
              allowPrivilegeEscalation: false,
              capabilities: {
                drop: ['ALL'],
              },
            },
            livenessProbe: {
              httpGet: {
                path: '/-/healthy',
                port: 9091,
                scheme: 'HTTPS',
              },
              initialDelaySeconds: 5,
              periodSeconds: 5,
              failureThreshold: 6,
              timeoutSeconds: 3,
            },
            readinessProbe: {
              httpGet: {
                path: '/-/ready',
                port: 9091,
                scheme: 'HTTPS',
              },
              initialDelaySeconds: 5,
              periodSeconds: 5,
              failureThreshold: 3,
              timeoutSeconds: 3,
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
                name: 'metrics',
              },
            ],
            args: [
              '--secure-listen-address=0.0.0.0:9092',
              '--upstream=http://127.0.0.1:9090',
              '--allow-paths=/metrics,/federate',
              '--config-file=/etc/kube-rbac-proxy/config.yaml',
              '--tls-cert-file=/etc/tls/private/tls.crt',
              '--tls-private-key-file=/etc/tls/private/tls.key',
              '--client-ca-file=/etc/tls/client/client-ca.crt',
              '--tls-cipher-suites=' + cfg.tlsCipherSuites,
            ],
            terminationMessagePolicy: 'FallbackToLogsOnError',
            volumeMounts: [
              {
                mountPath: '/etc/tls/private',
                name: 'secret-prometheus-k8s-tls',
              },
              {
                mountPath: '/etc/tls/client',
                name: 'configmap-metrics-client-ca',
                readOnly: true,
              },
              {
                mountPath: '/etc/kube-rbac-proxy',
                name: 'secret-' + $.kubeRbacProxySecret.metadata.name,
              },
            ],
          },
          {
            name: 'kube-rbac-proxy-thanos',
            image: cfg.kubeRbacProxyImage,
            resources: {
              requests: {
                memory: '10Mi',
                cpu: '1m',
              },
            },
            env: [{
              name: 'POD_IP',
              valueFrom: {
                fieldRef: {
                  fieldPath: 'status.podIP',
                },
              },
            }],
            ports: [
              {
                containerPort: 10903,
                name: 'thanos-proxy',
              },
            ],
            args: [
              '--secure-listen-address=[$(POD_IP)]:10903',
              '--upstream=http://127.0.0.1:10902',
              '--tls-cert-file=/etc/tls/private/tls.crt',
              '--tls-private-key-file=/etc/tls/private/tls.key',
              '--client-ca-file=/etc/tls/client/client-ca.crt',
              '--config-file=/etc/kube-rbac-proxy/config.yaml',
              '--tls-cipher-suites=' + cfg.tlsCipherSuites,
              '--allow-paths=/metrics',
              '--logtostderr=true',
            ],
            terminationMessagePolicy: 'FallbackToLogsOnError',
            volumeMounts: [
              {
                mountPath: '/etc/tls/private',
                name: 'secret-prometheus-k8s-thanos-sidecar-tls',
              },
              {
                mountPath: '/etc/kube-rbac-proxy',
                name: 'secret-' + $.kubeRbacProxySecret.metadata.name,
              },
            ],
          },
          {
            name: 'thanos-sidecar',
            args: [
              'sidecar',
              '--prometheus.url=http://localhost:9090/',
              '--tsdb.path=/prometheus',
              '--http-address=127.0.0.1:10902',
              '--grpc-server-tls-cert=/etc/tls/grpc/server.crt',
              '--grpc-server-tls-key=/etc/tls/grpc/server.key',
              '--grpc-server-tls-client-ca=/etc/tls/grpc/ca.crt',
            ],
            volumeMounts: [
              {
                mountPath: '/etc/tls/grpc',
                name: 'secret-grpc-tls',
              },
            ],
            resources: {
              requests: {
                cpu: '1m',
                memory: '25Mi',
              },
            },
          },
          {
            name: 'prometheus',
          },
        ],
      },
    },
  }
