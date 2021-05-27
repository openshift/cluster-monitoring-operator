local alertmanager = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/alertmanager.libsonnet';
// TODO: replace current addition of kube-rbac-proxy with upstream lib
// local krp = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/kube-rbac-proxy.libsonnet';

function(params)
  local cfg = params;

  alertmanager(cfg) {
    trustedCaBundle: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: {
        name: 'alertmanager-trusted-ca-bundle',
        namespace: cfg.namespace,
        labels: {
          'config.openshift.io/inject-trusted-cabundle': 'true',
        },
      },
      data: {
        'ca-bundle.crt': '',
      },
    },

    // OpenShift route to access the Alertmanager UI.

    route: {
      apiVersion: 'v1',
      kind: 'Route',
      metadata: {
        name: 'alertmanager-main',
        namespace: cfg.namespace,
      },
      spec: {
        to: {
          kind: 'Service',
          name: 'alertmanager-main',
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

    // The ServiceAccount needs this annotation, to signify the identity
    // provider, that when a users it doing the oauth flow through the oauth
    // proxy, that it should redirect to the alertmanager-main route on
    // successful authentication.
    serviceAccount+: {
      metadata+: {
        annotations+: {
          'serviceaccounts.openshift.io/oauth-redirectreference.alertmanager-main': '{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"alertmanager-main"}}',
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
    //
    // The ports are overridden, as due to the port binding of the oauth proxy
    // the serving port is 9094 instead of the 9093 default.

    service+: {
      metadata+: {
        annotations: {
          'service.beta.openshift.io/serving-cert-secret-name': 'alertmanager-main-tls',
        },
      },
      spec+: {
        ports: [
          {
            name: 'web',
            port: 9094,
            targetPort: 'web',
          },
          {
            name: 'tenancy',
            port: 9092,
            targetPort: 'tenancy',
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
        name: 'alertmanager-main-proxy',
        namespace: cfg.namespace,
        labels: { 'app.kubernetes.io/name': 'alertmanager-main' },
      },
      type: 'Opaque',
      data: {},
    },

    // In order for the oauth proxy to perform a TokenReview and
    // SubjectAccessReview for authN and authZ the alertmanager ServiceAccount
    // requires the `create` action on both of these.

    clusterRole: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRole',
      metadata: {
        name: 'alertmanager-main',
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
          // By default authenticated service accounts are assigned to the `restricted` SCC which implies MustRunAsRange.
          // This is problematic with statefulsets as UIDs (and file permissions) can change if SCCs are elevated.
          // Instead, this sets the `nonroot` SCC in conjunction with a static fsGroup and runAsUser security context below
          // to be immune against UID changes.
          apiGroups: ['security.openshift.io'],
          resources: ['securitycontextconstraints'],
          resourceNames: ['nonroot'],
          verbs: ['use'],
        },
      ],
    },

    clusterRoleBinding: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRoleBinding',
      metadata: {
        name: 'alertmanager-main',
      },
      roleRef: {
        apiGroup: 'rbac.authorization.k8s.io',
        kind: 'ClusterRole',
        name: 'alertmanager-main',
      },
      subjects: [{
        kind: 'ServiceAccount',
        name: 'alertmanager-main',
        namespace: cfg.namespace,
      }],
    },

    kubeRbacProxySecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'alertmanager-kube-rbac-proxy',
        namespace: cfg.namespace,
        labels: { 'app.kubernetes.io/name': 'alertmanager-main' },
      },
      type: 'Opaque',
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

    // This changes the alertmanager to be scraped with TLS, authN and authZ,
    // which are not present in kube-prometheus.
    serviceMonitor+: {
      spec+: {
        endpoints: [
          {
            port: 'web',
            interval: '30s',
            scheme: 'https',
            tlsConfig: {
              caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
              serverName: 'alertmanager-main',
            },
            bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
          },
        ],
      },
    },

    // These patches inject the oauth proxy as a sidecar and configures it with
    // TLS.
    alertmanager+: {
      spec+: {
        securityContext: {
          fsGroup: 65534,
          runAsNonRoot: true,
          runAsUser: 65534,
        },
        priorityClassName: 'system-cluster-critical',
        secrets: [
          'alertmanager-main-tls',
          'alertmanager-main-proxy',
          $.kubeRbacProxySecret.metadata.name,
        ],
        listenLocal: true,
        resources: {
          requests: {
            cpu: '4m',
            memory: '40Mi',
          },
        },
        containers: [
          {
            name: 'alertmanager-proxy',
            image: 'quay.io/openshift/oauth-proxy:latest',  //FIXME(paulfantom)
            ports: [
              {
                containerPort: 9095,
                name: 'web',
              },
            ],
            env: [
              {
                name: 'HTTP_PROXY',
                value: '',
              },
              {
                name: 'HTTPS_PROXY',
                value: '',
              },
              {
                name: 'NO_PROXY',
                value: '',
              },
            ],
            args: [
              '-provider=openshift',
              '-https-address=:9095',
              '-http-address=',
              '-email-domain=*',
              '-upstream=http://localhost:9093',
              '-openshift-sar={"resource": "namespaces", "verb": "get"}',
              '-openshift-delegate-urls={"/": {"resource": "namespaces", "verb": "get"}}',
              '-tls-cert=/etc/tls/private/tls.crt',
              '-tls-key=/etc/tls/private/tls.key',
              '-client-secret-file=/var/run/secrets/kubernetes.io/serviceaccount/token',
              '-cookie-secret-file=/etc/proxy/secrets/session_secret',
              '-openshift-service-account=alertmanager-main',
              '-openshift-ca=/etc/pki/tls/cert.pem',
              '-openshift-ca=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
            ],
            terminationMessagePolicy: 'FallbackToLogsOnError',
            resources: {
              requests: {
                cpu: '1m',
                memory: '20Mi',
              },
            },
            volumeMounts: [
              {
                mountPath: '/etc/tls/private',
                name: 'secret-alertmanager-main-tls',
              },
              {
                mountPath: '/etc/proxy/secrets',
                name: 'secret-alertmanager-main-proxy',
              },
            ],
          },
          {
            name: 'kube-rbac-proxy',
            image: 'quay.io/coreos/kube-rbac-proxy:v0.8.0',  //FIXME(paulfantom)
            resources: {
              requests: {
                cpu: '1m',
                memory: '15Mi',
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
              '--upstream=http://127.0.0.1:9096',
              '--config-file=/etc/kube-rbac-proxy/config.yaml',
              '--tls-cert-file=/etc/tls/private/tls.crt',
              '--tls-private-key-file=/etc/tls/private/tls.key',
              '--tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305',  //FIXME(paulfantom)
              '--logtostderr=true',
              '--v=10',
            ],
            terminationMessagePolicy: 'FallbackToLogsOnError',
            volumeMounts: [
              {
                mountPath: '/etc/kube-rbac-proxy',
                name: 'secret-' + $.kubeRbacProxySecret.metadata.name,
              },
              {
                mountPath: '/etc/tls/private',
                name: 'secret-alertmanager-main-tls',
              },
            ],
          },
          {
            name: 'prom-label-proxy',
            image: 'quay.io/coreos/prom-label-proxy:v0.2.0',  // FIXME(paulfantom)
            args: [
              '--insecure-listen-address=127.0.0.1:9096',
              '--upstream=http://127.0.0.1:9093',
              '--label=namespace',
            ],
            resources: {
              requests: {
                cpu: '1m',
                memory: '20Mi',
              },
            },
            terminationMessagePolicy: 'FallbackToLogsOnError',
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
    // TODO: remove podDisruptionBudget once https://github.com/prometheus-operator/kube-prometheus/pull/1156 is merged
    podDisruptionBudget+: {
      apiVersion: 'policy/v1',
    },
  }
