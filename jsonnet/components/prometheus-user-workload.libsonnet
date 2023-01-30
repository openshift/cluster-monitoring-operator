local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';

local prometheus = import 'github.com/jan--f/kube-prometheus/jsonnet/kube-prometheus/components/prometheus.libsonnet';

function(params)
  local cfg = params;
  prometheus(cfg) + {

    // Hide not needed resources
    prometheusRule:: {},
    prometheusRuleThanosSidecar:: {},
    endpointsEtcd:: {},
    serviceEtcd:: {},
    serviceMonitorEtcd:: {},
    serviceMonitorKubelet:: {},
    serviceMonitorApiserver:: {},
    serviceMonitorKubeScheduler:: {},
    serviceMonitorKubeControllerManager:: {},
    serviceMonitorCoreDNS:: {},
    secretEtcdCerts:: {},

    grpcTlsSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'prometheus-user-workload-grpc-tls',
        namespace: cfg.namespace,
        labels: { 'app.kubernetes.io/name': 'prometheus-k8s' },
      },
      type: 'Opaque',
      data: {},
    },

    configMap: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: {
        name: 'user-workload-monitoring-config',
        namespace: cfg.namespace,
      },
      data: {},
    },

    // Adding the serving certs annotation causes the serving certs controller
    // to generate a valid and signed serving certificate and put it in the
    // specified secret.
    //
    // The ClusterIP is explicitly set, as it signifies the
    // cluster-monitoring-operator, that when reconciling this service the
    // cluster IP needs to be retained.
    //
    // The ports are overridden, as due to the port binding of the oauth proxy
    // the serving port is 9091 instead of the 9090 default.
    service+: {
      metadata+: {
        annotations: {
          'service.beta.openshift.io/serving-cert-secret-name': 'prometheus-user-workload-tls',
        },
      },
      spec+: {
        ports: [
          {
            name: 'metrics',
            port: 9091,
            targetPort: 'metrics',
          },
          {
            name: 'federate',
            port: 9092,
            targetPort: 'federate',
          },
          {
            name: 'thanos-proxy',
            port: 10902,
            targetPort: 'thanos-proxy',
          },
        ],
        type: 'ClusterIP',
      },
    },

    federateRoute: {
      apiVersion: 'v1',
      kind: 'Route',
      metadata: {
        name: 'federate',
        namespace: cfg.namespace,
        labels: cfg.commonLabels,
      },
      spec: {
        path: '/federate',
        to: {
          kind: 'Service',
          name: $.service.metadata.name,
        },
        port: {
          targetPort: 'federate',
        },
        tls: {
          termination: 'Reencrypt',
          insecureEdgeTerminationPolicy: 'Redirect',
        },
      },
    },

    servingCertsCaBundle+: generateCertInjection.SCOCaBundleCM(cfg.namespace, 'serving-certs-ca-bundle'),

    // As Prometheus is protected by the kube-rbac-proxy it requires the
    // ability to create TokenReview and SubjectAccessReview requests.
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
          apiGroups: [''],
          resources: ['services', 'endpoints', 'pods'],
          verbs: ['get', 'list', 'watch'],
        },
        {
          apiGroups: ['monitoring.coreos.com'],
          resources: ['alertmanagers'],
          verbs: ['get'],
        },
        {
          // By default authenticated service accounts are assigned to the "restricte" SCC which implies MustRunAsRange.
          // This is problematic with statefulsets as UIDs (and file permissions) can change if SCCs are added/modified.
          // This allows the prometheus SA to use the "nonroot-v2" SCC, which will allow the prometheus pods to
          // run with both a static fsGroup and runAsUser making them immune against UID changes.
          // We need to use "-v2" as the UWM namespace works under PodPolicy profile "restricte", which will require
          // pods to run with seccompProfile "Defaul/Runtime", however pods are only allowed to specify a seccompProfile
          // when the SA uses an SCC "-v2"
          apiGroups: ['security.openshift.io'],
          resources: ['securitycontextconstraints'],
          resourceNames: ['nonroot-v2'],
          verbs: ['use'],
        },
        {
          nonResourceURLs: ['/api/v2/alerts'],
          verbs: ['create'],
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
              serverName: 'prometheus-user-workload',
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
          'service.beta.openshift.io/serving-cert-secret-name': 'prometheus-user-workload-thanos-sidecar-tls',
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
              serverName: 'prometheus-user-workload-thanos-sidecar',
              caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
              certFile: '/etc/prometheus/secrets/metrics-client-certs/tls.crt',
              keyFile: '/etc/prometheus/secrets/metrics-client-certs/tls.key',
            },
          },
        ],
      },
    },

    kubeRbacProxyMetricsSecret: generateSecret.staticAuthSecret(cfg.namespace, cfg.commonLabels, 'kube-rbac-proxy-metrics'),

    kubeRbacProxyFederateSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'kube-rbac-proxy-federate',
        namespace: cfg.namespace,
        labels: cfg.commonLabels,
      },
      type: 'Opaque',
      data: {},
      stringData: {
        'config.yaml': std.manifestYamlDoc({
          authorization: {
            resourceAttributes: {
              apiVersion: 'v1',
              resource: 'namespaces',
              verb: 'get',
            },
          },
        }),
      },
    },

    prometheus+: {
      spec+: {
        overrideHonorTimestamps: true,
        overrideHonorLabels: true,
        ignoreNamespaceSelectors: true,
        enforcedNamespaceLabel: 'namespace',
        ruleSelector: {
          matchLabels: {
            'openshift.io/prometheus-rule-evaluation-scope': 'leaf-prometheus',
          },
        },
        arbitraryFSAccessThroughSMs+: {
          deny: true,
        },
        thanos+: {
          resources: {
            requests: {
              cpu: '1m',
              memory: '100Mi',
            },
          },
        },
        alerting+: {
          alertmanagers:
            std.map(
              function(a) a {
                scheme: 'https',
                // the user-workload alertmanager configuration points to the openshift-monitoring namespace
                // since there is no dedicated alertmanager in the user-workload monitoring stack.
                namespace: 'openshift-monitoring',  //FIXME(paulfantom)
                tlsConfig: {
                  caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                  serverName: 'alertmanager-main.openshift-monitoring.svc',
                },
                bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
                apiVersion: 'v2',
              },
              super.alertmanagers,
            ),
        },
        securityContext: {
          fsGroup: 65534,
          runAsNonRoot: true,
          runAsUser: 65534,
          seccompProfile: {
            type: 'RuntimeDefault',
          },
        },
        secrets: [
          'prometheus-user-workload-tls',
          'prometheus-user-workload-thanos-sidecar-tls',
          $.kubeRbacProxyMetricsSecret.metadata.name,
          $.kubeRbacProxyFederateSecret.metadata.name,
        ],
        configMaps: ['serving-certs-ca-bundle', 'metrics-client-ca'],
        probeNamespaceSelector: cfg.namespaceSelector,
        podMonitorNamespaceSelector: cfg.namespaceSelector,
        serviceMonitorSelector: {},
        serviceMonitorNamespaceSelector: cfg.namespaceSelector,
        ruleNamespaceSelector: cfg.namespaceSelector,
        listenLocal: true,
        priorityClassName: 'openshift-user-critical',
        containers: [
          {
            name: 'kube-rbac-proxy-federate',
            image: cfg.kubeRbacProxyImage,
            resources: {
              requests: {
                memory: '10Mi',
                cpu: '1m',
              },
            },
            ports: [
              {
                containerPort: 9092,
                name: 'federate',
              },
            ],
            args: [
              '--secure-listen-address=0.0.0.0:9092',
              '--upstream=http://127.0.0.1:9090',
              '--allow-paths=/federate',
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
                name: 'secret-prometheus-user-workload-tls',
              },
              {
                mountPath: '/etc/tls/client',
                name: 'configmap-metrics-client-ca',
                readOnly: true,
              },
              {
                mountPath: '/etc/kube-rbac-proxy',
                name: 'secret-' + $.kubeRbacProxyFederateSecret.metadata.name,
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
            name: 'kube-rbac-proxy-metrics',
            image: cfg.kubeRbacProxyImage,
            resources: {
              requests: {
                memory: '10Mi',
                cpu: '1m',
              },
            },
            ports: [
              {
                containerPort: 9091,
                name: 'metrics',
              },
            ],
            args: [
              '--secure-listen-address=0.0.0.0:9091',
              '--upstream=http://127.0.0.1:9090',
              '--allow-paths=/metrics',
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
                name: 'secret-prometheus-user-workload-tls',
              },
              {
                mountPath: '/etc/tls/client',
                name: 'configmap-metrics-client-ca',
                readOnly: true,
              },
              {
                mountPath: '/etc/kube-rbac-proxy',
                name: 'secret-' + $.kubeRbacProxyMetricsSecret.metadata.name,
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
                containerPort: 10902,
                name: 'thanos-proxy',
              },
            ],
            args: [
              '--secure-listen-address=[$(POD_IP)]:10902',
              '--upstream=http://127.0.0.1:10902',
              '--tls-cert-file=/etc/tls/private/tls.crt',
              '--tls-private-key-file=/etc/tls/private/tls.key',
              '--client-ca-file=/etc/tls/client/client-ca.crt',
              '--tls-cipher-suites=' + cfg.tlsCipherSuites,
              '--allow-paths=/metrics',
              '--config-file=/etc/kube-rbac-proxy/config.yaml',
              '--logtostderr=true',
            ],
            terminationMessagePolicy: 'FallbackToLogsOnError',
            volumeMounts: [
              {
                mountPath: '/etc/tls/private',
                name: 'secret-prometheus-user-workload-thanos-sidecar-tls',
              },
              {
                mountPath: '/etc/tls/client',
                name: 'configmap-metrics-client-ca',
                readOnly: true,
              },
              {
                mountPath: '/etc/kube-rbac-proxy',
                name: 'secret-' + $.kubeRbacProxyMetricsSecret.metadata.name,
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
            resources: {
              requests: {
                memory: '17Mi',
                cpu: '1m',
              },
            },
            volumeMounts: [
              {
                mountPath: '/etc/tls/grpc',
                name: 'secret-grpc-tls',
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

    serviceAccount+: {
      // service account token is managed by the operator.
      automountServiceAccountToken: false,
    },

  }
