{
  prometheusUserWorkload+:: $.prometheus {
    name:: 'user-workload',
    namespace:: $._config.namespaceUserWorkload,
    roleBindingNamespaces:: [$._config.namespaceUserWorkload],

    grpcTlsSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'prometheus-user-workload-grpc-tls',
        namespace: $._config.namespaceUserWorkload,
        labels: { 'k8s-app': 'prometheus-k8s' },
      },
      type: 'Opaque',
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
            name: 'thanos-proxy',
            port: 10902,
            targetPort: 'thanos-proxy',
          },
        ],
        type: 'ClusterIP',
      },
    },

    servingCertsCaBundle+: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata+: {
        name: 'serving-certs-ca-bundle',
        namespace: $._config.namespaceUserWorkload,
        annotations: { 'service.alpha.openshift.io/inject-cabundle': 'true' },
      },
      data: { 'service-ca.crt': '' },
    },

    // As Prometheus is protected by the kube-rbac-proxy it requires the
    // ability to create TokenReview and SubjectAccessReview requests.
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

    // This avoids creating service monitors which are already managed by the respective operators.
    rules:: {},
    endpointsEtcd:: {},
    serviceEtcd:: {},
    serviceMonitorEtcd:: {},
    serviceMonitorKubelet:: {},
    serviceMonitorApiserver:: {},
    serviceMonitorKubeScheduler:: {},
    serviceMonitorKubeControllerManager:: {},
    serviceMonitorCoreDNS:: {},
    secretEtcdCerts:: {},

    // This changes the Prometheuses to be scraped with TLS, authN and
    // authZ, which are not present in kube-prometheus.

    serviceMonitor+:
      {
        spec+: {
          endpoints: [
            {
              port: 'metrics',
              interval: '30s',
              scheme: 'https',
              tlsConfig: {
                caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                serverName: 'prometheus-user-workload',
              },
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
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

    serviceMonitorThanosSidecar+:
      {
        spec+: {
          jobLabel:: null,
          endpoints: [
            {
              port: 'thanos-proxy',
              interval: '30s',
              scheme: 'https',
              tlsConfig: {
                caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                serverName: 'prometheus-user-workload-thanos-sidecar',
              },
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            },
          ],
        },
      },

    prometheus+:
      {
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
            image: $._config.imageRepos.openshiftThanos + ':' + $._config.versions.openshiftThanos,
            version: $._config.versions.openshiftThanos,
            // disable thanos object storage
            objectStorageConfig:: null,
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
                  namespace: $._config.namespace,
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
          resources: {
            requests: {
              memory: '30Mi',
              cpu: '6m',
            },
          },
          securityContext: {
            fsGroup: 65534,
            runAsNonRoot: true,
            runAsUser: 65534,
          },
          secrets: [
            'prometheus-user-workload-tls',
            'prometheus-user-workload-thanos-sidecar-tls',
          ],
          configMaps: ['serving-certs-ca-bundle'],
          serviceMonitorSelector: {},
          serviceMonitorNamespaceSelector: {},
          ruleNamespaceSelector: {},
          listenLocal: true,
          priorityClassName: 'openshift-user-critical',
          containers: [
            {
              name: 'kube-rbac-proxy',
              image: $._config.imageRepos.kubeRbacProxy + ':' + $._config.versions.kubeRbacProxy,
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
                '--tls-cert-file=/etc/tls/private/tls.crt',
                '--tls-private-key-file=/etc/tls/private/tls.key',
                '--tls-cipher-suites=' + std.join(',', $._config.tlsCipherSuites),
                '--allow-paths=/metrics',
              ],
              terminationMessagePolicy: 'FallbackToLogsOnError',
              volumeMounts: [
                {
                  mountPath: '/etc/tls/private',
                  name: 'secret-prometheus-user-workload-tls',
                },
              ],
            },
            {
              name: 'kube-rbac-proxy-thanos',
              image: $._config.imageRepos.kubeRbacProxy + ':' + $._config.versions.kubeRbacProxy,
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
                '--tls-cipher-suites=' + std.join(',', $._config.tlsCipherSuites),
                '--allow-paths=/metrics',
                '--logtostderr=true',
              ],
              terminationMessagePolicy: 'FallbackToLogsOnError',
              volumeMounts: [
                {
                  mountPath: '/etc/tls/private',
                  name: 'secret-prometheus-user-workload-thanos-sidecar-tls',
                },
              ],
            },
            {
              name: 'thanos-sidecar',
              args: [
                'sidecar',
                '--prometheus.url=http://localhost:9090/',
                '--tsdb.path=/prometheus',
                '--grpc-address=[$(POD_IP)]:10901',
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
  },
}
