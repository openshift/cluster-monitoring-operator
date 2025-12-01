local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';
local ruler = import 'github.com/thanos-io/kube-thanos/jsonnet/kube-thanos/kube-thanos-rule.libsonnet';
local withDescription = (import '../utils/add-annotations.libsonnet').withDescription;
local requiredClusterRoles = (import '../utils/add-annotations.libsonnet').requiredClusterRoles;

local defaults = {
  volumeClaimTemplate: {},
  serviceMonitor: true,
};

function(params)
  local cfg = defaults + params;
  local tr = ruler(cfg);

  tr {
    mixin:: (import 'github.com/thanos-io/thanos/mixin/alerts/rule.libsonnet') {
      targetGroups: {
        namespace: tr.config.namespace,
      },
      rule+:: {
        selector: 'job="thanos-ruler"',
      },
    },

    thanosRulerPrometheusRule: {
      apiVersion: 'monitoring.coreos.com/v1',
      kind: 'PrometheusRule',
      metadata: {
        name: tr.config.name,
        namespace: tr.config.namespace,
      },
      spec: $.mixin.prometheusAlerts,
    },

    route: {
      apiVersion: 'v1',
      kind: 'Route',
      metadata: {
        name: tr.config.name,
        namespace: tr.config.namespace,
        annotations: withDescription(
          'Expose the `/api` endpoints of the `%s` service via a router.' % $.route.spec.to.name,
        ),
      },
      spec: {
        // restrict to Thanos Rule API endpoint only
        path: '/api',
        to: {
          kind: 'Service',
          name: tr.config.name,
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
        name: tr.config.name,
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
          resourceNames: ['nonroot-v2'],
          resources: ['securitycontextconstraints'],
          verbs: ['use'],
        },
      ],
    },

    clusterRoleBinding: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRoleBinding',
      metadata: {
        name: tr.config.name,
      },
      roleRef: {
        apiGroup: 'rbac.authorization.k8s.io',
        kind: 'ClusterRole',
        name: tr.config.name,
      },
      subjects: [{
        kind: 'ServiceAccount',
        name: tr.config.name,
        namespace: cfg.namespace,
      }],
    },

    clusterRoleBindingMonitoring: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRoleBinding',
      metadata: {
        name: 'thanos-ruler-monitoring',
      },
      roleRef: {
        apiGroup: 'rbac.authorization.k8s.io',
        kind: 'ClusterRole',
        name: 'cluster-monitoring-view',
      },
      subjects: [{
        kind: 'ServiceAccount',
        name: tr.config.name,
        namespace: tr.config.namespace,
      }],
    },

    // RoleBinding to send alerts to the platform Alertmanager.
    alertmanagerRoleBinding: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'RoleBinding',
      metadata: {
        name: 'alertmanager-thanos-ruler',
        namespace: 'openshift-monitoring',
      },
      roleRef: {
        apiGroup: 'rbac.authorization.k8s.io',
        kind: 'Role',
        name: 'monitoring-alertmanager-edit',
      },
      subjects: [{
        kind: 'ServiceAccount',
        name: tr.config.name,
        namespace: tr.config.namespace,
      }],
    },

    // RoleBinding to send alerts to the user-workload Alertmanager.
    alertmanagerUserWorkloadRoleBinding: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'RoleBinding',
      metadata: {
        name: 'user-workload-alertmanager-thanos-ruler',
        namespace: tr.config.namespace,
      },
      roleRef: {
        apiGroup: 'rbac.authorization.k8s.io',
        kind: 'Role',
        name: 'monitoring-alertmanager-api-writer',
      },
      subjects: [{
        kind: 'ServiceAccount',
        name: tr.config.name,
        namespace: tr.config.namespace,
      }],
    },

    grpcTlsSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'thanos-ruler-grpc-tls',
        namespace: tr.config.namespace,
        labels: {
          'app.kubernetes.io/name': tr.config.name,
        },
      },
      type: 'Opaque',
      data: {},
    },

    // alertmanager config holds the http configuration
    // for communication between thanos ruler and alertmanager.
    alertmanagersConfigSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'thanos-ruler-alertmanagers-config',
        namespace: tr.config.namespace,
        labels: {
          'app.kubernetes.io/name': tr.config.name,
        },
      },
      type: 'Opaque',
      data: {},
      stringData: {
        'alertmanagers.yaml': std.manifestYamlDoc({
          alertmanagers: [{
            http_config: {
              bearer_token_file: '/var/run/secrets/kubernetes.io/serviceaccount/token',
              tls_config: {
                ca_file: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                server_name: 'alertmanager-main.openshift-monitoring.svc',
              },
            },
            static_configs: ['dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc'],
            scheme: 'https',
            api_version: 'v2',
          }],
        }),
      },
    },

    // query config which holds http configuration
    // for communication between thanos ruler and thanos querier.
    queryConfigSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'thanos-ruler-query-config',
        namespace: tr.config.namespace,
        labels: {
          'app.kubernetes.io/name': tr.config.name,
        },
      },
      type: 'Opaque',
      data: {},
      stringData: {
        'query.yaml': std.manifestYamlDoc([{
          http_config: {
            bearer_token_file: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            tls_config: {
              ca_file: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
              server_name: 'thanos-querier.openshift-monitoring.svc',
            },
          },
          static_configs: ['thanos-querier.openshift-monitoring.svc:9091'],
          scheme: 'https',
        }]),
      },
    },

    serviceAccount+: {
      metadata+: {
        annotations: {
          'serviceaccounts.openshift.io/oauth-redirectreference.thanos-ruler-': '',
        },
      },
    },

    service+: {
      metadata+: {
        annotations: {
          'service.beta.openshift.io/serving-cert-secret-name': 'thanos-ruler-tls',
        } + withDescription(
          |||
            Expose the Thanos Ruler web server within the cluster on the following ports:
            * Port %d provides access to all Thanos Ruler endpoints. %s
            * Port %d provides access to the `/metrics` endpoint only. This port is for internal use, and no other usage is guaranteed.

            This also exposes the gRPC endpoints on port %d. This port is for internal use, and no other usage is guaranteed.
          ||| % [
            $.service.spec.ports[0].port,
            requiredClusterRoles(['cluster-monitoring-view'], true),
            $.service.spec.ports[1].port,
            $.service.spec.ports[2].port,
          ],
        ),
      },
      spec+: {
        ports: [{
          name: 'web',
          port: 9091,
          targetPort: 'web',
        }, {
          name: 'metrics',
          port: 9092,
          targetPort: 'metrics',
        }, {
          name: 'grpc',
          port: 10901,
          targetPort: 'grpc',
        }],
        selector: {
          'app.kubernetes.io/name': tr.config.name,
          'thanos-ruler': 'user-workload',
        },
        sessionAffinity: 'ClientIP',
        type: 'ClusterIP',
        clusterIP:: {},
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

    kubeRbacProxyMetricsSecret: generateSecret.staticAuthSecret(cfg.namespace, cfg.commonLabels, 'thanos-ruler-kube-rbac-proxy-metrics'),

    kubeRbacProxyWebSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'thanos-' + cfg.crName + '-kube-rbac-proxy-web',
        namespace: tr.config.namespace,
        labels: cfg.commonLabels,
      },
      type: 'Opaque',
      data: {},
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

    thanosRuler: {
      apiVersion: 'monitoring.coreos.com/v1',
      kind: 'ThanosRuler',
      metadata: {
        name: cfg.crName,
        namespace: tr.config.namespace,
        labels: {
          thanosRulerName: cfg.crName,
        },
        annotations+: {
          'operator.prometheus.io/controller-id': 'openshift-user-workload-monitoring/prometheus-operator',
        },
      },
      spec: {
        affinity: {
          podAntiAffinity: {
            requiredDuringSchedulingIgnoredDuringExecution: [{
              labelSelector: {
                matchLabels: cfg.selectorLabels,
              },
              namespaces: [cfg.namespace],
              topologyKey: 'kubernetes.io/hostname',
            }],
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
        replicas: cfg.replicas,
        resources: {
          requests: {
            memory: '21Mi',
            cpu: '1m',
          },
        },
        image: cfg.image,
        grpcServerTlsConfig: {
          certFile: '/etc/tls/grpc/server.crt',
          keyFile: '/etc/tls/grpc/server.key',
          caFile: '/etc/tls/grpc/ca.crt',
        },
        alertmanagersConfig: {
          key: 'alertmanagers.yaml',
          name: 'thanos-ruler-alertmanagers-config',
        },
        queryConfig: {
          key: 'query.yaml',
          name: 'thanos-ruler-query-config',
        },
        enforcedNamespaceLabel: 'namespace',
        listenLocal: true,
        ruleSelector: cfg.resourceSelector {
          matchExpressions+:
            [
              {
                key: 'openshift.io/prometheus-rule-evaluation-scope',
                operator: 'NotIn',
                values: ['leaf-prometheus'],
              },
            ],
        },
        ruleNamespaceSelector: cfg.namespaceSelector,
        version: cfg.version,
        volumes: [
          generateCertInjection.SCOCaBundleVolume('serving-certs-ca-bundle'),
          {
            name: 'secret-thanos-ruler-tls',
            secret: {
              secretName: 'thanos-ruler-tls',
            },
          },
          {
            name: 'secret-' + $.kubeRbacProxyMetricsSecret.metadata.name,
            secret: {
              secretName: $.kubeRbacProxyMetricsSecret.metadata.name,
            },
          },
          {
            name: 'secret-' + $.kubeRbacProxyWebSecret.metadata.name,
            secret: {
              secretName: $.kubeRbacProxyWebSecret.metadata.name,
            },
          },
          {
            name: 'metrics-client-ca',
            configMap: {
              name: 'metrics-client-ca',
            },
          },
        ],
        serviceAccountName: tr.config.name,
        priorityClassName: 'openshift-user-critical',
        containers: [
          {
            // Note: this is performing strategic-merge-patch for thanos-ruler
            // container. the rest of the container configuration is managed by
            // prometheus-operator based on $.thanosRuler.spec.
            name: tr.config.name,
            volumeMounts: [
              {
                mountPath: '/etc/tls/private',
                name: 'secret-thanos-ruler-tls',
              },
              {
                mountPath: '/etc/tls/grpc',
                name: 'secret-grpc-tls',
              },
              {
                mountPath: '/etc/prometheus/configmaps/serving-certs-ca-bundle',
                name: 'serving-certs-ca-bundle',
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
            name: 'kube-rbac-proxy-web',
            image: cfg.kubeRbacProxyImage,
            ports: [{
              containerPort: $.service.spec.ports[0].port,
              name: 'web',
            }],
            args: [
              '--secure-listen-address=0.0.0.0:9091',
              '--upstream=http://127.0.0.1:10902',
              '--config-file=/etc/kube-rbac-proxy/config.yaml',
              '--tls-cert-file=/etc/tls/private/tls.crt',
              '--tls-private-key-file=/etc/tls/private/tls.key',
            ],
            resources: {
              requests: {
                cpu: '1m',
                memory: '12Mi',
              },
            },
            volumeMounts: [
              {
                mountPath: '/etc/tls/private',
                name: 'secret-thanos-ruler-tls',
                readOnly: true,
              },
              {
                mountPath: '/etc/kube-rbac-proxy',
                name: 'secret-' + $.kubeRbacProxyWebSecret.metadata.name,
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
          {
            // TODO: merge this metric proxy with the kube-rbac-proxy-web
            // container when the issue below is fixed:
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
                containerPort: 9092,
                name: 'metrics',
              },
            ],
            args: [
              '--secure-listen-address=0.0.0.0:9092',
              '--upstream=http://127.0.0.1:10902',
              '--config-file=/etc/kube-rbac-proxy/config.yaml',
              '--tls-cert-file=/etc/tls/private/tls.crt',
              '--tls-private-key-file=/etc/tls/private/tls.key',
              '--client-ca-file=/etc/tls/client/client-ca.crt',
              '--allow-paths=/metrics',
            ],
            volumeMounts: [
              {
                mountPath: '/etc/tls/private',
                name: 'secret-thanos-ruler-tls',
              },
              {
                mountPath: '/etc/kube-rbac-proxy',
                name: 'secret-' + $.kubeRbacProxyMetricsSecret.metadata.name,
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

    podDisruptionBudget: {
      apiVersion: 'policy/v1',
      kind: 'PodDisruptionBudget',
      metadata: {
        name: 'thanos-ruler-' + cfg.crName,
        namespace: cfg.namespace,
        labels: {
          thanosRulerName: cfg.crName,
        },
      },
      spec: {
        minAvailable: 1,
        selector: {
          matchLabels: cfg.selectorLabels,
        },
      },
    },

    statefulSet:: {},

    networkPolicyDownstream: {
      apiVersion: 'networking.k8s.io/v1',
      kind: 'NetworkPolicy',
      metadata: {
        name: 'thanos-ruler',
        namespace: cfg.namespace,
      },
      spec: {
        podSelector: {
          matchLabels: {
            'app.kubernetes.io/name': 'thanos-ruler',
          },
        },
        policyTypes: [
          'Ingress',
          'Egress',
        ],
        ingress: [
          {
            ports: [
              // allow prometheus to scrape thanos-ruler endpoint, 9092(port name: metrics) port
              {
                port: 'metrics',
                protocol: 'TCP',
              },
            ],
          },
        ],
        egress: [
          {},
        ],
      },
    },
  }
