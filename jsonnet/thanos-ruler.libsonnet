// TODO(paulfantom): This should use upstream kube-thanos project.

function(params) {
  local cfg = params,

  mixin:: (import 'github.com/thanos-io/thanos/mixin/alerts/rule.libsonnet') {
    rule+:: {
      selector: 'job="thanos-ruler"',
    },
  },

  thanosRulerPrometheusRule: {
    apiVersion: 'monitoring.coreos.com/v1',
    kind: 'PrometheusRule',
    metadata: {
      name: 'thanos-ruler',
      namespace: 'openshift-user-workload-monitoring',
    },
    spec: $.mixin.prometheusAlerts,
  },

  trustedCaBundle: {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      name: 'thanos-ruler-trusted-ca-bundle',
      namespace: cfg.namespace,
      labels: {
        'config.openshift.io/inject-trusted-cabundle': 'true',
      },
    },
    data: {
      'ca-bundle.crt': '',
    },
  },

  route: {
    apiVersion: 'v1',
    kind: 'Route',
    metadata: {
      name: 'thanos-ruler',
      namespace: cfg.namespace,
    },
    spec: {
      to: {
        kind: 'Service',
        name: 'thanos-ruler',
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
      name: 'thanos-ruler',
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
      name: 'thanos-ruler',
    },
    roleRef: {
      apiGroup: 'rbac.authorization.k8s.io',
      kind: 'ClusterRole',
      name: 'thanos-ruler',
    },
    subjects: [{
      kind: 'ServiceAccount',
      name: 'thanos-ruler',
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
      name: 'thanos-ruler',
      namespace: cfg.namespace,
    }],
  },

  grpcTlsSecret: {
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: {
      name: 'thanos-ruler-grpc-tls',
      namespace: cfg.namespace,
      labels: {
        'app.kubernetes.io/name': 'thanos-ruler',
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
      namespace: cfg.namespace,
      labels: {
        'app.kubernetes.io/name': 'thanos-ruler',
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
      namespace: cfg.namespace,
      labels: {
        'app.kubernetes.io/name': 'thanos-ruler',
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
      namespace: cfg.namespace,
      labels: {
        'app.kubernetes.io/name': 'thanos-ruler',
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
      namespace: cfg.namespace,
      labels: {
        'app.kubernetes.io/name': 'thanos-ruler',
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

  serviceAccount: {
    apiVersion: 'v1',
    kind: 'ServiceAccount',
    metadata: {
      name: 'thanos-ruler',
      namespace: cfg.namespace,
      annotations: {
        'serviceaccounts.openshift.io/oauth-redirectreference.thanos-ruler': '{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"thanos-ruler"}}',
      },
    },
  },

  service: {
    apiVersion: 'v1',
    kind: 'Service',
    metadata: {
      name: 'thanos-ruler',
      namespace: cfg.namespace,
      annotations: {
        'service.beta.openshift.io/serving-cert-secret-name': 'thanos-ruler-tls',
      },
      labels: cfg.labels,
    },
    spec: {
      ports: [{
        name: 'web',
        port: cfg.ports.web,
        targetPort: 'web',
      }, {
        name: 'grpc',
        port: cfg.ports.grpc,
        targetPort: 'grpc',
      }],
      selector: cfg.selectorLabels,
      sessionAffinity: 'ClientIP',
      type: 'ClusterIP',
    },
  },

  serviceMonitor: {
    apiVersion: 'monitoring.coreos.com/v1',
    kind: 'ServiceMonitor',
    metadata: {
      name: 'thanos-ruler',
      namespace: cfg.namespace,
      labels: {
        'app.kubernetes.io/name': 'thanos-ruler',
      },
    },
    spec: {
      selector: {
        matchLabels: cfg.labels,
      },
      endpoints: [
        {
          port: 'web',
          interval: '30s',
          scheme: 'https',
          tlsConfig: {
            caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
            serverName: 'server-name-replaced-at-runtime',
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
      name: cfg.name,
      namespace: cfg.namespace,
      labels: {
        thanosRulerName: cfg.name,
      },
    },
    spec: {
      securityContext: {
        fsGroup: 65534,
        runAsNonRoot: true,
        runAsUser: 65534,
      },
      replicas: 2,
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
        {
          name: 'serving-certs-ca-bundle',
          configmap: {
            name: 'serving-certs-ca-bundle',
          },
        },
        {
          name: 'secret-thanos-ruler-tls',
          secret: {
            secretName: 'thanos-ruler-tls',
          },
        },
        {
          name: 'secret-thanos-ruler-oauth-cookie',
          secret: {
            secretName: 'thanos-ruler-oauth-cookie',
          },
        },
        {
          name: 'secret-thanos-ruler-oauth-htpasswd',
          secret: {
            secretName: 'thanos-ruler-oauth-htpasswd',
          },
        },
      ],
      serviceAccountName: 'thanos-ruler',
      priorityClassName: 'openshift-user-critical',
      containers: [
        {
          name: 'thanos-ruler',
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
            containerPort: cfg.ports.web,
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

  // statefulSet from kube-thanos is not needed because thanosruler custom resource
  // is used instead.
  //statefulSet:: {},

}
