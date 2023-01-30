local alertmanager = import 'github.com/jan--f/kube-prometheus/jsonnet/kube-prometheus/components/alertmanager.libsonnet';
// TODO: replace current addition of kube-rbac-proxy with upstream lib
// local krp = import 'github.com/jan--f/kube-prometheus/jsonnet/kube-prometheus/components/kube-rbac-proxy.libsonnet';
local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';

function(params)
  local cfg = params {
    replicas: 2,
  };

  alertmanager(cfg) {
    // Hide resources which are not needed because already deployed in the openshift-monitoring namespace.
    prometheusRule:: {},

    trustedCaBundle: generateCertInjection.trustedCNOCaBundleCM(cfg.namespace, 'alertmanager-trusted-ca-bundle'),

    serviceAccount+: {
      // automountServiceAccountToken is set to true as kube-rbac-proxy sidecar
      // requires connection to kubernetes API
      automountServiceAccountToken: true,
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
          'service.beta.openshift.io/serving-cert-secret-name': 'alertmanager-user-workload-tls',
        },
      },
      spec+: {
        ports: [
          {
            name: 'web',
            port: 9095,
            targetPort: 'web',
          },
          {
            name: 'tenancy',
            port: 9092,
            targetPort: 'tenancy',
          },
          {
            name: 'metrics',
            port: 9097,
            targetPort: 'metrics',
          },
        ],
        type: 'ClusterIP',
      },
    },

    // This changes the alertmanager to be scraped with TLS, authN and authZ,
    // which are not present in kube-prometheus.
    serviceMonitor+: {
      spec+: {
        endpoints: [
          {
            port: 'metrics',
            interval: '30s',
            scheme: 'https',
            tlsConfig: {
              caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
              serverName: 'alertmanager-' + cfg.name,
              certFile: '/etc/prometheus/secrets/metrics-client-certs/tls.crt',
              keyFile: '/etc/prometheus/secrets/metrics-client-certs/tls.key',
            },
          },
        ],
      },
    },


    // In order for kube-rbac-proxy to perform a TokenReview and
    // SubjectAccessReview for authN and authZ the alertmanager ServiceAccount
    // requires the `create` action on both of these.

    clusterRole: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRole',
      metadata: {
        name: 'alertmanager-' + cfg.name,
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
          // Instead, this sets the `nonroot-v2` SCC in conjunction with a static fsGroup and runAsUser security context below
          // to be immune against UID changes.
          apiGroups: ['security.openshift.io'],
          resources: ['securitycontextconstraints'],
          resourceNames: ['nonroot-v2'],
          verbs: ['use'],
        },
      ],
    },

    clusterRoleBinding: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRoleBinding',
      metadata: {
        name: 'alertmanager-' + cfg.name,
      },
      roleRef: {
        apiGroup: 'rbac.authorization.k8s.io',
        kind: 'ClusterRole',
        name: 'alertmanager-' + cfg.name,
      },
      subjects: [{
        kind: 'ServiceAccount',
        name: 'alertmanager-' + cfg.name,
        namespace: cfg.namespace,
      }],
    },

    kubeRbacProxyTenancySecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'alertmanager-kube-rbac-proxy-tenancy',
        namespace: cfg.namespace,
        labels: { 'app.kubernetes.io/name': 'alertmanager-' + cfg.name },
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

    kubeRbacProxyMetricSecret: generateSecret.staticAuthSecret(cfg.namespace, cfg.commonLabels, 'alertmanager-kube-rbac-proxy-metric') + {
      metadata+: {
        labels: { 'app.kubernetes.io/name': 'alertmanager-' + cfg.name },
      },
    },

    alertmanager+: {
      spec+: {
        securityContext: {
          fsGroup: 65534,
          runAsNonRoot: true,
          runAsUser: 65534,
          seccompProfile: {
            type: 'RuntimeDefault',
          },
        },
        priorityClassName: 'system-cluster-critical',
        secrets: [
          'alertmanager-user-workload-tls',
          $.kubeRbacProxyTenancySecret.metadata.name,
          $.kubeRbacProxyMetricSecret.metadata.name,
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
            image: cfg.kubeRbacProxyImage,
            resources: {
              requests: {
                cpu: '1m',
                memory: '15Mi',
              },
            },
            ports: [
              {
                containerPort: 9095,
                name: 'web',
              },
            ],
            args: [
              '--secure-listen-address=0.0.0.0:9095',
              '--upstream=http://127.0.0.1:9093',
              '--tls-cert-file=/etc/tls/private/tls.crt',
              '--tls-private-key-file=/etc/tls/private/tls.key',
              '--tls-cipher-suites=' + cfg.tlsCipherSuites,
              '--logtostderr=true',
            ],
            terminationMessagePolicy: 'FallbackToLogsOnError',
            volumeMounts: [
              {
                mountPath: '/etc/tls/private',
                name: 'secret-alertmanager-user-workload-tls',
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
            name: 'tenancy-proxy',
            image: cfg.kubeRbacProxyImage,
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
              '--tls-cipher-suites=' + cfg.tlsCipherSuites,
              '--logtostderr=true',
            ],
            terminationMessagePolicy: 'FallbackToLogsOnError',
            volumeMounts: [
              {
                mountPath: '/etc/kube-rbac-proxy',
                name: 'secret-' + $.kubeRbacProxyTenancySecret.metadata.name,
              },
              {
                mountPath: '/etc/tls/private',
                name: 'secret-alertmanager-user-workload-tls',
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
            name: 'kube-rbac-proxy-metric',
            image: cfg.kubeRbacProxyImage,
            resources: {
              requests: {
                cpu: '1m',
                memory: '15Mi',
              },
            },
            ports: [
              {
                containerPort: 9097,
                name: 'metrics',
              },
            ],
            args: [
              '--secure-listen-address=0.0.0.0:9097',
              '--upstream=http://127.0.0.1:9093',
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
                name: 'secret-alertmanager-user-workload-tls',
                readOnly: true,
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
          {
            name: 'prom-label-proxy',
            image: cfg.promLabelProxyImage,
            args: [
              '--insecure-listen-address=127.0.0.1:9096',
              '--upstream=http://127.0.0.1:9093',
              '--label=namespace',
              '--error-on-replace',
            ],
            resources: {
              requests: {
                cpu: '1m',
                memory: '20Mi',
              },
            },
            terminationMessagePolicy: 'FallbackToLogsOnError',
            securityContext: {
              allowPrivilegeEscalation: false,
              capabilities: {
                drop: ['ALL'],
              },
            },
          },
        ],
        volumes+: [
          {
            name: 'metrics-client-ca',
            configMap: {
              name: 'metrics-client-ca',
            },
          },
        ],
      },
    },
  }
