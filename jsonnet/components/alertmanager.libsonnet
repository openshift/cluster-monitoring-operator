local alertmanager = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/alertmanager.libsonnet';
// TODO: replace current addition of kube-rbac-proxy with upstream lib
// local krp = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/kube-rbac-proxy.libsonnet';
local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';
local withDescription = (import '../utils/add-annotations.libsonnet').withDescription;
local testFilePlaceholder = (import '../utils/add-annotations.libsonnet').testFilePlaceholder;
local requiredRoles = (import '../utils/add-annotations.libsonnet').requiredRoles;
local requiredClusterRoles = (import '../utils/add-annotations.libsonnet').requiredClusterRoles;

function(params)
  local cfg = params {
    replicas: 2,
  };

  alertmanager(cfg) {
    trustedCaBundle: generateCertInjection.trustedCNOCaBundleCM(cfg.namespace, 'alertmanager-trusted-ca-bundle'),

    // OpenShift route to access the Alertmanager UI.
    route: {
      apiVersion: 'v1',
      kind: 'Route',
      metadata: {
        name: 'alertmanager-main',
        namespace: cfg.namespace,
        annotations: withDescription(
          'Expose the `/api` endpoints of the `alertmanager-main` service via a router.',
        ),
      },
      spec: {
        path: '/api',
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

    serviceAccount+: {
      // Alertmanager can mount the token into the pod since
      // https://github.com/prometheus-operator/prometheus-operator/pull/5474
      // and v0.66.0
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
    // The ports are overridden because the kube-rbac-proxy sidecar listens on
    // serving port 9094 instead of the default port (9093).

    service+: {
      metadata+: {
        annotations: {
          'service.beta.openshift.io/serving-cert-secret-name': 'alertmanager-main-tls',
        } + withDescription(
          |||
            Expose the Alertmanager web server within the cluster on the following ports:
            * Port %d provides access to all the Alertmanager endpoints. %s
            %s
            * Port %d provides access to the Alertmanager endpoints restricted to a given project. %s
            * Port %d provides access to the `/metrics` endpoint only. This port is for internal use, and no other usage is guaranteed.
          ||| % [
            $.service.spec.ports[0].port,
            requiredRoles([['monitoring-alertmanager-view', 'for read-only operations'], 'monitoring-alertmanager-edit'], 'openshift-monitoring'),
            testFilePlaceholder('openshift-monitoring', 'alertmanager-main', $.service.spec.ports[0].port),
            $.service.spec.ports[1].port,
            requiredClusterRoles(['monitoring-rules-edit', 'monitoring-edit'], false, ''),
            $.service.spec.ports[2].port,
          ],
        ),
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
          {
            name: 'metrics',
            port: 9097,
            targetPort: 'metrics',
          },
        ],
        type: 'ClusterIP',
      },
    },

    // In order for the kube-rbac-proxy sidecar to perform a TokenReview and
    // SubjectAccessReview for authN and authZ, the alertmanager ServiceAccount
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
        labels: cfg.commonLabels { 'app.kubernetes.io/name': 'alertmanager-main' },
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
        labels: { 'app.kubernetes.io/name': 'alertmanager-main' },
      },
    },

    kubeRbacProxyWebSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'alertmanager-kube-rbac-proxy-web',
        namespace: 'openshift-monitoring',
        labels: cfg.commonLabels,
      },
      type: 'Opaque',
      data: {},
      stringData: {
        'config.yaml': std.manifestYamlDoc({
          authorization: {
            resourceAttributes: {
              apiGroup: 'monitoring.coreos.com',
              resource: 'alertmanagers',
              subresource: 'api',
              namespace: 'openshift-monitoring',
              name: 'main',
            },
          },
        }),
      },
    },

    serviceMonitor+: {
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

    alertmanager+: {
      metadata+: {
        annotations+: {
          'operator.prometheus.io/controller-id': 'openshift-monitoring/prometheus-operator',
        },
      },
      spec+: {
        podMetadata+: {
          annotations+: {
            'openshift.io/required-scc': 'nonroot',
          },
        },
        securityContext: {
          fsGroup: 65534,
          runAsNonRoot: true,
          runAsUser: 65534,
        },
        priorityClassName: 'system-cluster-critical',
        web: {
          httpConfig: {
            headers: {
              contentSecurityPolicy: "frame-ancestors 'none'",
            },
          },
        },
        secrets: [
          'alertmanager-main-tls',
          $.kubeRbacProxySecret.metadata.name,
          $.kubeRbacProxyMetricSecret.metadata.name,
          $.kubeRbacProxyWebSecret.metadata.name,
        ],
        listenLocal: true,
        resources: {
          requests: {
            cpu: '4m',
            memory: '40Mi',
          },
        },
        automountServiceAccountToken: true,
        containers: [
          {
            name: 'alertmanager',
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
          },
          {
            name: 'kube-rbac-proxy-web',
            image: cfg.kubeRbacProxyImage,
            resources: {
              requests: {
                cpu: '1m',
                memory: '20Mi',
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
              '--config-file=/etc/kube-rbac-proxy/config.yaml',
              '--tls-cert-file=/etc/tls/private/tls.crt',
              '--tls-private-key-file=/etc/tls/private/tls.key',
              '--tls-cipher-suites=' + cfg.tlsCipherSuites,
              // Liveness and readiness endpoints are always allowed.
              '--ignore-paths=' + std.join(',', ['/-/healthy', '/-/ready']),
            ],
            volumeMounts: [
              {
                mountPath: '/etc/kube-rbac-proxy',
                name: 'secret-' + $.kubeRbacProxyWebSecret.metadata.name,
                readOnly: true,
              },
              {
                mountPath: '/etc/tls/private',
                name: 'secret-alertmanager-main-tls',
                readOnly: true,
              },
            ],
          },
          {
            name: 'kube-rbac-proxy',
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
            ],
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
            // TODO: merge this metric proxy with the kube-rbac-proxy-web when
            // the issue below is fixed:
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
              '--allow-paths=/metrics',
            ],
            volumeMounts: [
              {
                mountPath: '/etc/kube-rbac-proxy',
                name: 'secret-' + $.kubeRbacProxyMetricSecret.metadata.name,
                readOnly: true,
              },
              {
                mountPath: '/etc/tls/private',
                name: 'secret-alertmanager-main-tls',
                readOnly: true,
              },
              {
                mountPath: '/etc/tls/client',
                name: 'metrics-client-ca',
                readOnly: true,
              },
            ],
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
          },
        ],
        volumes+: [
          {
            name: 'metrics-client-ca',
            configMap: {
              name: 'metrics-client-ca',
            },
          },
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
        volumeMounts+: [
          {
            name: $.trustedCaBundle.metadata.name,
            mountPath: '/etc/pki/ca-trust/extracted/pem/',
          },
        ],
      },
    },
    networkPolicy: {
      apiVersion: 'networking.k8s.io/v1',
      kind: 'NetworkPolicy',
      metadata: {
        annotations: {
          'include.release.openshift.io/hypershift': 'true',
          'include.release.openshift.io/ibm-cloud-managed': 'true',
          'include.release.openshift.io/self-managed-high-availability': 'true',
          'include.release.openshift.io/single-node-developer': 'true',
        },
        name: 'alertmanager-access',
        namespace: cfg.namespace,
      },
      spec: {
        podSelector: {
          matchLabels: {
            'app.kubernetes.io/name': 'alertmanager',
          },
        },
        policyTypes: [
          'Ingress',
          'Egress',
        ],
        ingress: [
          {
            ports: [
              {
                port: '9092',
                protocol: 'TCP',
              },
              {
                port: '9094',
                protocol: 'TCP',
              },
              {
                port: '9094',
                protocol: 'UDP',
              },
              {
                port: '9095',
                protocol: 'TCP',
              },
              {
                port: '9097',
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
