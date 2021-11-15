local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';
local ruler = import 'github.com/thanos-io/kube-thanos/jsonnet/kube-thanos/kube-thanos-rule.libsonnet';

local defaults = {
  volumeClaimTemplate: {},
  serviceMonitor: true,
};

function(params)
  local cfg = defaults + params;
  local tr = ruler(cfg);

  tr {
    mixin:: (import 'github.com/thanos-io/thanos/mixin/alerts/rule.libsonnet') {
      targetGroups: {},
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

    trustedCaBundle: generateCertInjection.trustedCNOCaBundleCM(cfg.namespace, 'thanos-ruler-trusted-ca-bundle'),

    route: {
      apiVersion: 'v1',
      kind: 'Route',
      metadata: {
        name: tr.config.name,
        namespace: tr.config.namespace,
      },
      spec: {
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
          resourceNames: ['nonroot'],
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

    // holds the secret which is used encrypt/decrypt cookies
    // issued by the oauth proxy.
    oauthCookieSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'thanos-ruler-oauth-cookie',
        namespace: tr.config.namespace,
        labels: {
          'app.kubernetes.io/name': tr.config.name,
        },
      },
      type: 'Opaque',
      data: {},
    },

    // holds the htpasswd configuration
    // which includes a static secret used to authenticate/authorize
    // requests originating from grafana.
    oauthHtpasswdSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'thanos-ruler-oauth-htpasswd',
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
          'serviceaccounts.openshift.io/oauth-redirectreference.thanos-ruler': '{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"thanos-ruler"}}',
        },
      },
    },

    service+: {
      metadata+: {
        annotations: {
          'service.beta.openshift.io/serving-cert-secret-name': 'thanos-ruler-tls',
        },
      },
      spec+: {
        ports: [{
          name: 'web',
          port: 9091,
          targetPort: 'web',
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
              port: 'web',
              interval: '30s',
              scheme: 'https',
              tlsConfig: {
                caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                serverName: 'server-name-replaced-at-runtime',
                certFile: '/etc/prometheus/secrets/metrics-client-certs/tls.crt',
                keyFile: '/etc/prometheus/secrets/metrics-client-certs/tls.key',
              },
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            },
          ],
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
        securityContext: {
          fsGroup: 65534,
          runAsNonRoot: true,
          runAsUser: 65534,
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
        ruleSelector: {
          matchExpressions:
            [
              {
                key: 'openshift.io/prometheus-rule-evaluation-scope',
                operator: 'NotIn',
                values: ['leaf-prometheus'],
              },
            ],
        },
        ruleNamespaceSelector: cfg.namespaceSelector,
        volumes: [
          generateCertInjection.SCOCaBundleVolume('serving-certs-ca-bundle'),
          {
            name: 'secret-thanos-ruler-tls',
            secret: {
              secretName: 'thanos-ruler-tls',
            },
          },
          {
            name: 'secret-thanos-ruler-oauth-cookie',
            secret: {
              secretName: $.oauthCookieSecret.metadata.name,
            },
          },
          {
            name: 'secret-thanos-ruler-oauth-htpasswd',
            secret: {
              secretName: $.oauthHtpasswdSecret.metadata.name,
            },
          },
        ],
        serviceAccountName: tr.config.name,
        priorityClassName: 'openshift-user-critical',
        containers: [
          {
            // Note: this is performing strategic-merge-patch for thanos-ruler container.
            // Remainder of the container configuration is managed by prometheus-operator based on $.thanosRuler.spec
            name: tr.config.name,
            terminationMessagePolicy: 'FallbackToLogsOnError',
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
          },
          {
            name: 'thanos-ruler-proxy',
            image: 'quay.io/openshift/oauth-proxy:latest',  //FIXME(paulfantom)
            ports: [{
              containerPort: $.service.spec.ports[0].port,
              name: 'web',
            }],
            env: [
              { name: 'HTTP_PROXY', value: '' },
              { name: 'HTTPS_PROXY', value: '' },
              { name: 'NO_PROXY', value: '' },
            ],
            args: [
              '-provider=openshift',
              '-https-address=:9091',
              '-http-address=',
              '-email-domain=*',
              '-upstream=http://localhost:10902',
              '-openshift-sar={"resource": "namespaces", "verb": "get"}',
              '-openshift-delegate-urls={"/": {"resource": "namespaces", "verb": "get"}}',
              '-tls-cert=/etc/tls/private/tls.crt',
              '-tls-key=/etc/tls/private/tls.key',
              '-client-secret-file=/var/run/secrets/kubernetes.io/serviceaccount/token',
              '-cookie-secret-file=/etc/proxy/secrets/session_secret',
              '-openshift-service-account=thanos-ruler',
              '-openshift-ca=/etc/pki/tls/cert.pem',
              '-openshift-ca=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
            ],
            terminationMessagePolicy: 'FallbackToLogsOnError',
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
              },
              {
                mountPath: '/etc/proxy/secrets',
                name: 'secret-thanos-ruler-oauth-cookie',
              },
            ],
          },
          {
            // Note: this is performing strategic-merge-patch for config-reloader container.
            // Remainder of the container configuration is managed by prometheus-operator based on $.thanosRuler.spec
            name: 'config-reloader',
            resources: {
              requests: {
                cpu: '1m',
                memory: '10Mi',
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

  }
