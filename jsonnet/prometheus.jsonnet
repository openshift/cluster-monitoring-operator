local metrics = import 'telemeter-client/metrics.jsonnet';

{
  // Configure the correct label selectors for Thanos sidecar alerts.
  sidecar+:: {
    selector: 'job=~"prometheus-(k8s|user-workload)-thanos-sidecar"',
  },

  prometheusK8s+:: {
    trustedCaBundle: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: {
        name: 'prometheus-trusted-ca-bundle',
        namespace: $._config.namespace,
        labels: {
          'config.openshift.io/inject-trusted-cabundle': 'true',
        },
      },
      data: {
        'ca-bundle.crt': '',
      },
    },

    grpcTlsSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'prometheus-k8s-grpc-tls',
        namespace: $._config.namespace,
        labels: { 'k8s-app': 'prometheus-k8s' },
      },
      type: 'Opaque',
      data: {},
    },

    // OpenShift route to access the Prometheus UI.

    route: {
      apiVersion: 'v1',
      kind: 'Route',
      metadata: {
        name: 'prometheus-k8s',
        namespace: $._config.namespace,
      },
      spec: {
        to: {
          kind: 'Service',
          name: 'prometheus-k8s',
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
    // provider, that when a users it doing the oauth flow through the
    // oauth proxy, that it should redirect to the prometheus-k8s route on
    // successful authentication.

    serviceAccount+: {
      metadata+: {
        annotations+: {
          'serviceaccounts.openshift.io/oauth-redirectreference.prometheus-k8s': '{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"prometheus-k8s"}}',
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
    // the serving port is 9091 instead of the 9090 default.

    service+: {
      metadata+: {
        annotations: {
          'service.beta.openshift.io/serving-cert-secret-name': 'prometheus-k8s-tls',
        },
      },
      spec+: {
        ports: [
          {
            name: 'web',
            port: 9091,
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

    servingCertsCaBundle+: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata+: {
        name: 'serving-certs-ca-bundle',
        namespace: $._config.namespace,
        annotations: { 'service.alpha.openshift.io/inject-cabundle': 'true' },
      },
      data: { 'service-ca.crt': '' },
    },

    // Even though this bundle will be frequently rotated by the CSR
    // controller, there is no need to add a ConfigMap reloader to
    // the Prometheus Pods because Prometheus automatically reloads
    // its cert pool every 5 seconds.
    kubeletServingCaBundle+: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata+: {
        name: 'kubelet-serving-ca-bundle',
        namespace: $._config.namespace,
      },
      data: { 'ca-bundle.crt': '' },
    },

    // As Prometheus is protected by the oauth proxy it requires the
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

    // The proxy secret is there to encrypt session created by the oauth proxy.

    proxySecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'prometheus-k8s-proxy',
        namespace: $._config.namespace,
        labels: { 'k8s-app': 'prometheus-k8s' },
      },
      type: 'Opaque',
      data: {},
    },

    htpasswdSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'prometheus-k8s-htpasswd',
        namespace: $._config.namespace,
        labels: { 'k8s-app': 'prometheus-k8s' },
      },
      type: 'Opaque',
      data: {},
    },

    kubeRbacProxySecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'kube-rbac-proxy',
        namespace: $._config.namespace,
        labels: { 'k8s-app': 'prometheus-k8s' },
      },
      type: 'Opaque',
      data: {},
      stringData: {
        'config.yaml': std.manifestYamlDoc({
          authorization: {
            rewrites: {
              byQueryParameter: {
                name: 'namespace',
              },
            },
            resourceAttributes: {
              apiVersion: 'metrics.k8s.io/v1beta1',
              resource: 'pods',
              namespace: '{{ .Value }}',
            },
          },
        }),
      },
    },

    // This changes the kubelet's certificates to be validated when
    // scraping.

    serviceMonitorKubelet+:
      {
        spec+: {
          endpoints:
            std.map(
              function(e)
                e {
                  tlsConfig+: {
                    caFile: '/etc/prometheus/configmaps/kubelet-serving-ca-bundle/ca-bundle.crt',
                    insecureSkipVerify: false,
                  },
                },
              super.endpoints,
            ) +
            [{
              interval: '30s',
              port: 'https-metrics',
              relabelings: [
                {
                  sourceLabels: ['__address__'],
                  action: 'replace',
                  targetLabel: '__address__',
                  regex: '(.+)(?::\\d+)',
                  replacement: '$1:9537',
                },
                {
                  sourceLabels: ['endpoint'],
                  action: 'replace',
                  targetLabel: 'endpoint',
                  replacement: 'crio',
                },
                {
                  action: 'replace',
                  targetLabel: 'job',
                  replacement: 'crio',
                },
              ],
            }],
        },
      },

    serviceMonitorEtcd+:
      {
        metadata+: {
          namespace: $._config.namespace,
        },
        spec+: {
          namespaceSelector: {
            matchNames: ['openshift-etcd'],
          },
        },
      },

    // This avoids creating service monitors which are already managed by the respective operators.

    serviceMonitorApiserver:: {},
    serviceMonitorKubeScheduler:: {},
    serviceMonitorKubeControllerManager:: {},
    serviceMonitorCoreDNS:: {},

    // This changes the Prometheuses to be scraped with TLS, authN and
    // authZ, which are not present in kube-prometheus.

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
                serverName: 'prometheus-k8s',
              },
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            },
          ],
        },
      },

    serviceThanosSidecar+: {
      metadata+: {
        annotations+: {
          'service.beta.openshift.io/serving-cert-secret-name': 'prometheus-k8s-thanos-sidecar-tls',
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
                serverName: 'prometheus-k8s-thanos-sidecar',
              },
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            },
          ],
        },
      },

    // These patches inject the oauth proxy as a sidecar and configures it with
    // TLS. Additionally as the Alertmanager is protected with TLS, authN and
    // authZ it requires some additonal configuration.

    prometheus+:
      {
        spec+: {
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
                  tlsConfig: {
                    caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                    serverName: 'alertmanager-main',
                  },
                  bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
                  apiVersion: 'v2',
                },
                super.alertmanagers,
              ),
          },
          resources: {
            requests: {
              memory: '1Gi',
              cpu: '70m',
            },
          },
          securityContext: {
            fsGroup: 65534,
            runAsNonRoot: true,
            runAsUser: 65534,
          },
          secrets+: [
            'prometheus-k8s-tls',
            'prometheus-k8s-proxy',
            'prometheus-k8s-htpasswd',
            'prometheus-k8s-thanos-sidecar-tls',
            'kube-rbac-proxy',
          ],
          configMaps: ['serving-certs-ca-bundle', 'kubelet-serving-ca-bundle'],
          serviceMonitorSelector: {},
          serviceMonitorNamespaceSelector: {},
          ruleSelector: {},
          ruleNamespaceSelector: {},
          listenLocal: true,
          priorityClassName: 'openshift-user-critical',
          containers: [
            {
              name: 'prometheus-proxy',
              image: $._config.imageRepos.openshiftOauthProxy + ':' + $._config.versions.openshiftOauthProxy,
              resources: {
                requests: {
                  memory: '20Mi',
                  cpu: '1m',
                },
              },
              ports: [
                {
                  containerPort: 9091,
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
                '-https-address=:9091',
                '-http-address=',
                '-email-domain=*',
                '-upstream=http://localhost:9090',
                '-htpasswd-file=/etc/proxy/htpasswd/auth',
                '-openshift-service-account=prometheus-k8s',
                '-openshift-sar={"resource": "namespaces", "verb": "get"}',
                '-openshift-delegate-urls={"/": {"resource": "namespaces", "verb": "get"}}',
                '-tls-cert=/etc/tls/private/tls.crt',
                '-tls-key=/etc/tls/private/tls.key',
                '-client-secret-file=/var/run/secrets/kubernetes.io/serviceaccount/token',
                '-cookie-secret-file=/etc/proxy/secrets/session_secret',
                '-openshift-ca=/etc/pki/tls/cert.pem',
                '-openshift-ca=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
                '-skip-auth-regex=^/metrics',
              ],
              terminationMessagePolicy: 'FallbackToLogsOnError',
              volumeMounts: [
                {
                  mountPath: '/etc/tls/private',
                  name: 'secret-prometheus-k8s-tls',
                },
                {
                  mountPath: '/etc/proxy/secrets',
                  name: 'secret-prometheus-k8s-proxy',
                },
                {
                  mountPath: '/etc/proxy/htpasswd',
                  name: 'secret-prometheus-k8s-htpasswd',
                },
              ],
            },
            {
              name: 'kube-rbac-proxy',
              image: $._config.imageRepos.kubeRbacProxy + ':' + $._config.versions.kubeRbacProxy,
              resources: {
                requests: {
                  memory: '20Mi',
                  cpu: '1m',
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
                '--upstream=http://127.0.0.1:9095',
                '--config-file=/etc/kube-rbac-proxy/config.yaml',
                '--tls-cert-file=/etc/tls/private/tls.crt',
                '--tls-private-key-file=/etc/tls/private/tls.key',
                '--tls-cipher-suites=' + std.join(',', $._config.tlsCipherSuites),
                '--logtostderr=true',
                '--v=10',
              ],
              terminationMessagePolicy: 'FallbackToLogsOnError',
              volumeMounts: [
                {
                  mountPath: '/etc/tls/private',
                  name: 'secret-prometheus-k8s-tls',
                },
                {
                  mountPath: '/etc/kube-rbac-proxy',
                  name: 'secret-' + $.prometheusK8s.kubeRbacProxySecret.metadata.name,
                },
              ],
            },
            {
              name: 'prom-label-proxy',
              image: $._config.imageRepos.promLabelProxy + ':' + $._config.versions.promLabelProxy,
              args: [
                '--insecure-listen-address=127.0.0.1:9095',
                '--upstream=http://127.0.0.1:9090',
                '--label=namespace',
              ],
              resources: {
                requests: {
                  memory: '20Mi',
                  cpu: '1m',
                },
              },
              terminationMessagePolicy: 'FallbackToLogsOnError',
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
                  name: 'secret-prometheus-k8s-thanos-sidecar-tls',
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
              volumeMounts: [
                {
                  mountPath: '/etc/tls/grpc',
                  name: 'secret-grpc-tls',
                },
              ],
              resources: {
                requests: {
                  cpu: '1m',
                },
              },
            },
            {
              name: 'prometheus',
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
