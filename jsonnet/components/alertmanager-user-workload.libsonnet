local alertmanager = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/alertmanager.libsonnet';
// TODO: replace current addition of kube-rbac-proxy with upstream lib
// local krp = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/kube-rbac-proxy.libsonnet';
local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';
local withDescription = (import '../utils/add-annotations.libsonnet').withDescription;
local requiredRoles = (import '../utils/add-annotations.libsonnet').requiredRoles;
local requiredClusterRoles = (import '../utils/add-annotations.libsonnet').requiredClusterRoles;

function(params)
  local cfg = params {
    replicas: 2,
  };

  alertmanager(cfg) {
    // Hide resources which are not needed because already deployed in the openshift-monitoring namespace.
    prometheusRule:: {},

    trustedCaBundle: generateCertInjection.trustedCNOCaBundleCM(cfg.namespace, 'alertmanager-trusted-ca-bundle'),

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
        } + withDescription(
          |||
            Expose the user-defined Alertmanager web server within the cluster on the following ports:
            * Port %d provides access to the Alertmanager endpoints. %s
            * Port %d provides access to the Alertmanager endpoints restricted to a given project. %s
            * Port %d provides access to the `/metrics` endpoint only. This port is for internal use, and no other usage is guaranteed.
          ||| % [
            $.service.spec.ports[0].port,
            requiredRoles([['monitoring-alertmanager-api-reader', 'for read-only operations'], 'monitoring-alertmanager-api-writer'], 'openshift-user-workload-monitoring'),
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

    kubeRbacProxySecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'alertmanager-kube-rbac-proxy',
        namespace: cfg.namespace,
        labels: { 'app.kubernetes.io/name': 'alertmanager-' + cfg.name },
      },
      type: 'Opaque',
      stringData: {
        'config.yaml': std.manifestYamlDoc({
          authorization: {
            resourceAttributes: {
              apiGroup: 'monitoring.coreos.com',
              resource: 'alertmanagers',
              subresource: 'api',
              name: cfg.name,
              namespace: cfg.namespace,
            },
          },
        }),
      },
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
      metadata+: {
        annotations+: {
          'operator.prometheus.io/controller-id': 'openshift-user-workload-monitoring/prometheus-operator',
        },
      },
      spec+: {
        // The value of alertmanagerConfigSelector is defined at runtime by the Cluster Monitoring Operator.
        alertmanagerConfigSelector: null,
        automountServiceAccountToken: true,
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
          $.kubeRbacProxySecret.metadata.name,
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
              '--config-file=/etc/kube-rbac-proxy/config.yaml',
            ],
            volumeMounts: [
              {
                mountPath: '/etc/tls/private',
                name: 'secret-alertmanager-user-workload-tls',
                readOnly: true,
              },
              {
                mountPath: '/etc/kube-rbac-proxy',
                name: 'secret-' + $.kubeRbacProxySecret.metadata.name,
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
            ],
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
    networkPolicyDownstream: {
      apiVersion: 'networking.k8s.io/v1',
      kind: 'NetworkPolicy',
      metadata: {
        name: 'alertmanager-user-workload',
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
              // allow access to the Alertmanager endpoints restricted to a given project,
              // port number 9092(port name: tenancy)
              {
                port: 'tenancy',
                protocol: 'TCP',
              },
              // allow prometheus to scrape user workload alertmanager 9097(port name: metrics) port
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
