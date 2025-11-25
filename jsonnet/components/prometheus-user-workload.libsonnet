local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';
local withDescription = (import '../utils/add-annotations.libsonnet').withDescription;
local requiredClusterRoles = (import '../utils/add-annotations.libsonnet').requiredClusterRoles;

local prometheus = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/prometheus.libsonnet';

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

    trustedCaBundle: generateCertInjection.trustedCNOCaBundleCM(cfg.namespace, 'prometheus-user-workload-trusted-ca-bundle'),

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
    // The ports are overridden because the kube-rbac-proxy container listens
    // on port 9091 while Prometheus listens on localhost:9090.
    service+: {
      metadata+: {
        annotations: {
          'service.beta.openshift.io/serving-cert-secret-name': 'prometheus-user-workload-tls',
        } + withDescription(
          |||
            Expose the Prometheus web server within the cluster on the following ports:
            * Port %d provides access to the `/metrics` endpoint only. This port is for internal use, and no other usage is guaranteed.
            * Port %d provides access to the `/federate` endpoint only. %s

            This also exposes the `/metrics` endpoint of the Thanos sidecar web server on port %d. This port is for internal use, and no other usage is guaranteed.
          ||| % [
            $.service.spec.ports[0].port,
            $.service.spec.ports[1].port,
            requiredClusterRoles(['cluster-monitoring-view'], true),
            $.service.spec.ports[2].port,
          ],
        ),
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
        annotations: withDescription(
          'Expose the `/federate` endpoint of the `%s` service via a router.' % $.service.metadata.name,
        ),
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
          apiGroups: ['discovery.k8s.io'],
          resources: ['endpointslices'],
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
      ],
    },

    // RoleBinding to send alerts to the platform Alertmanager.
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

    // RoleBinding to send alerts to the user-workload Alertmanager.
    alertmanagerUserWorkloadRoleBinding: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'RoleBinding',
      metadata: {
        name: 'alertmanager-user-workload-prometheus' + cfg.name,
        namespace: cfg.namespace,
      },
      roleRef: {
        apiGroup: 'rbac.authorization.k8s.io',
        kind: 'Role',
        name: 'monitoring-alertmanager-api-writer',
      },
      subjects: [{
        kind: 'ServiceAccount',
        name: 'prometheus-' + cfg.name,
        namespace: cfg.namespace,
      }],
    },

    serviceMonitor+: {
      spec+: {
        serviceDiscoveryRole: 'EndpointSlice',
        endpoints: [
          {
            port: 'metrics',
            interval: '30s',
            scheme: 'https',
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
        serviceDiscoveryRole: 'EndpointSlice',
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
      metadata+: {
        annotations+: {
          'operator.prometheus.io/controller-id': 'openshift-user-workload-monitoring/prometheus-operator',
        },
      },
      spec+: {
        // Enable some experimental features.
        // More at https://prometheus.io/docs/prometheus/latest/feature_flags/
        enableFeatures+: ['extra-scrape-metrics', 'delayed-compaction', 'use-uncached-io'],
        overrideHonorTimestamps: true,
        overrideHonorLabels: true,
        ignoreNamespaceSelectors: true,
        enforcedNamespaceLabel: 'namespace',
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
        podMetadata+: {
          annotations+: {
            'openshift.io/required-scc': 'nonroot-v2',
          },
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
        probeSelector: cfg.resourceSelector,
        probeNamespaceSelector: cfg.namespaceSelector,
        podMonitorSelector: cfg.resourceSelector,
        podMonitorNamespaceSelector: cfg.namespaceSelector,
        serviceMonitorSelector: cfg.resourceSelector,
        serviceMonitorNamespaceSelector: cfg.namespaceSelector,
        ruleSelector: cfg.resourceSelector {
          matchExpressions+: [
            {
              key: 'openshift.io/prometheus-rule-evaluation-scope',
              operator: 'In',
              values: ['leaf-prometheus'],
            },
          ],
        },
        ruleNamespaceSelector: cfg.namespaceSelector,
        scrapeConfigSelector: null,
        scrapeConfigNamespaceSelector: null,
        listenLocal: true,
        priorityClassName: 'openshift-user-critical',
        additionalArgs: [
          // This aligns any scrape timestamps <= 15ms to the a multiple of
          // the scrape interval. This optmizes tsdb compression.
          // 15ms was chosen for being a conservative value given our default
          // recommended scrape interval of 30s. This adds at most a .1% error
          // to the timestamp if users pick half that interval.
          // For tighter scrape intervals this error goes up.
          {
            name: 'scrape.timestamp-tolerance',
            value: '15ms',
          },
        ],
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
              '--tls-cipher-suites=' + cfg.tlsCipherSuites,
              '--allow-paths=/metrics',
              '--config-file=/etc/kube-rbac-proxy/config.yaml',
            ],
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

          // NOTE: It is important to have the container - prometheus specified
          // so that CMO will apply all the required customizations.
          // See e.g pkg/manifests/manifests.go where the startup probe is added
          {
            name: 'prometheus',
            env: [{
              name: 'HTTP_PROXY',
              value: '',
            }, {
              name: 'HTTPS_PROXY',
              value: '',
            }, {
              name: 'NO_PROXY',
              value: '',
            }],
            volumeMounts+: [
              {
                name: $.trustedCaBundle.metadata.name,
                mountPath: '/etc/pki/ca-trust/extracted/pem/',
              },
            ],
          },
        ],
        // As we do not have control over the targets, this is meant to maintain the v2 behavior.
        // We will discuss later whether and how we want to enable the v3 behavior.
        scrapeClasses: [
          {
            name: 'global-config',
            default: true,
            fallbackScrapeProtocol: 'PrometheusText1.0.0',
          },
        ],
        volumes+: [
          {
            name: $.trustedCaBundle.metadata.name,
            configMap: {
              name: $.trustedCaBundle.metadata.name,
              items: [{
                key: 'ca-bundle.crt',
                path: 'tls-ca-bundle.pem',
              }],
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
