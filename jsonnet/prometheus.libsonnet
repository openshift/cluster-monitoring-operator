local metrics = import 'github.com/openshift/telemeter/jsonnet/telemeter/metrics.jsonnet';

local prometheus = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/prometheus.libsonnet';

function(params)
  local cfg = params;

  prometheus(cfg) + {
    trustedCaBundle: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: {
        name: 'prometheus-trusted-ca-bundle',
        namespace: cfg.namespace,
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
        namespace: cfg.namespace,
        labels: { 'app.kubernetes.io/name': 'prometheus-k8s' },
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
        namespace: cfg.namespace,
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
        namespace: cfg.namespace,
        annotations: { 'service.alpha.openshift.io/inject-cabundle': 'true' },
      },
      data: { 'service-ca.crt': '' },
    },

    // Even though this bundle will be frequently rotated by the CSR
    // controller, there is no need to add a ConfigMap reloader to
    // the Prometheus Pods because Prometheus automatically reloads
    // its cert pool every 5 seconds.
    // TODO(paulfantom): Should this be moved to control-plane?
    kubeletServingCaBundle+: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata+: {
        name: 'kubelet-serving-ca-bundle',
        namespace: cfg.namespace,
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

    // The proxy secret is there to encrypt session created by the oauth proxy.
    proxySecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'prometheus-k8s-proxy',
        namespace: cfg.namespace,
        labels: { 'app.kubernetes.io/name': 'prometheus-k8s' },
      },
      type: 'Opaque',
      data: {},
    },

    htpasswdSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'prometheus-k8s-htpasswd',
        namespace: cfg.namespace,
        labels: { 'app.kubernetes.io/name': 'prometheus-k8s' },
      },
      type: 'Opaque',
      data: {},
    },

    kubeRbacProxySecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'kube-rbac-proxy',
        namespace: cfg.namespace,
        labels: { 'app.kubernetes.io/name': 'prometheus-k8s' },
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
            static: [
              {
                user: {
                  name: 'system:serviceaccount:openshift-monitoring:prometheus-k8s',
                },
                apiGroup: 'metrics.k8s.io/v1beta1',
                resource: 'pods',
                resourceRequest: true,
              },
            ],
          },
        }),
      },
    },

    // This changes the Prometheuses to be scraped with TLS, authN and
    // authZ, which are not present in kube-prometheus.

    serviceMonitor+: {
      spec+: {
        endpoints: [
          {
            port: 'web',
            interval: '30s',
            scheme: 'https',
            tlsConfig: {
              caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
              serverName: 'prometheus-k8s',
              certFile: '/etc/prometheus/secrets/metrics-client-certs/tls.crt',
              keyFile: '/etc/prometheus/secrets/metrics-client-certs/tls.key',
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

    serviceMonitorThanosSidecar+: {
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
              certFile: '/etc/prometheus/secrets/metrics-client-certs/tls.crt',
              keyFile: '/etc/prometheus/secrets/metrics-client-certs/tls.key',
            },
            bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
          },
        ],
      },
    },

    // These patches inject the oauth proxy as a sidecar and configures it with
    // TLS. Additionally as the Alertmanager is protected with TLS, authN and
    // authZ it requires some additonal configuration.
    //
    // Note that Grafana is enabled by default, but may be explicitly disabled
    // by the user.  We need to inject an htpasswd file for the oauth-proxy when
    // it is enabled, so by default the operator also adds a few things at
    // runtime: a volume and volume-mount for the secret, and an argument to the
    // proxy container pointing to the mounted htpasswd file.  If Grafana is
    // disabled, these things are not injected.
    prometheus+: {
      spec+: {
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
          // NOTE: The following is injected at runtime if Grafana is enabled:
          // 'prometheus-k8s-htpasswd'
          'kube-etcd-client-certs',  //TODO(paulfantom): move it to etcd addon
          'prometheus-k8s-tls',
          'prometheus-k8s-proxy',
          'prometheus-k8s-thanos-sidecar-tls',
          'kube-rbac-proxy',
          'metrics-client-certs',
        ],
        configMaps: ['serving-certs-ca-bundle', 'kubelet-serving-ca-bundle'],
        probeNamespaceSelector: cfg.namespaceSelector,
        podMonitorNamespaceSelector: cfg.namespaceSelector,
        serviceMonitorSelector: {},
        serviceMonitorNamespaceSelector: cfg.namespaceSelector,
        ruleSelector: {},
        ruleNamespaceSelector: cfg.namespaceSelector,
        listenLocal: true,
        priorityClassName: 'system-cluster-critical',
        containers: [
          {
            name: 'prometheus-proxy',
            image: 'quay.io/openshift/oauth-proxy:latest',  //FIXME(paulfantom)
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
              // NOTE: The following is injected at runtime if Grafana is enabled:
              // '-htpasswd-file=/etc/proxy/htpasswd/auth'
              '-provider=openshift',
              '-https-address=:9091',
              '-http-address=',
              '-email-domain=*',
              '-upstream=http://localhost:9090',
              '-openshift-service-account=prometheus-k8s',
              '-openshift-sar={"resource": "namespaces", "verb": "get"}',
              '-openshift-delegate-urls={"/": {"resource": "namespaces", "verb": "get"}}',
              '-tls-cert=/etc/tls/private/tls.crt',
              '-tls-key=/etc/tls/private/tls.key',
              '-client-secret-file=/var/run/secrets/kubernetes.io/serviceaccount/token',
              '-cookie-secret-file=/etc/proxy/secrets/session_secret',
              '-openshift-ca=/etc/pki/tls/cert.pem',
              '-openshift-ca=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
            ],
            terminationMessagePolicy: 'FallbackToLogsOnError',
            volumeMounts: [
              // NOTE: The following is injected at runtime if Grafana is enabled:
              // {
              //   mountPath: '/etc/proxy/htpasswd',
              //   name: 'secret-prometheus-k8s-htpasswd',
              // },
              {
                mountPath: '/etc/tls/private',
                name: 'secret-prometheus-k8s-tls',
              },
              {
                mountPath: '/etc/proxy/secrets',
                name: 'secret-prometheus-k8s-proxy',
              },
            ],
          },
          {
            name: 'kube-rbac-proxy',
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
                name: 'tenancy',
              },
            ],
            args: [
              '--secure-listen-address=0.0.0.0:9092',
              '--upstream=http://127.0.0.1:9095',
              '--config-file=/etc/kube-rbac-proxy/config.yaml',
              '--tls-cert-file=/etc/tls/private/tls.crt',
              '--tls-private-key-file=/etc/tls/private/tls.key',
              '--tls-cipher-suites=' + cfg.tlsCipherSuites,
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
                name: 'secret-' + $.kubeRbacProxySecret.metadata.name,
              },
            ],
          },
          {
            name: 'prom-label-proxy',
            image: cfg.promLabelProxyImage,
            args: [
              '--insecure-listen-address=127.0.0.1:9095',
              '--upstream=http://127.0.0.1:9090',
              '--label=namespace',
            ],
            resources: {
              requests: {
                memory: '15Mi',
                cpu: '1m',
              },
            },
            terminationMessagePolicy: 'FallbackToLogsOnError',
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
                containerPort: 10902,
                name: 'thanos-proxy',
              },
            ],
            args: [
              '--secure-listen-address=[$(POD_IP)]:10902',
              '--upstream=http://127.0.0.1:10902',
              '--tls-cert-file=/etc/tls/private/tls.crt',
              '--tls-private-key-file=/etc/tls/private/tls.key',
              '--tls-cipher-suites=' + cfg.tlsCipherSuites,
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
                memory: '25Mi',
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
    // Removing PDB since it doesn't allow cluster upgrade when hard pod anti affinity is not set https://github.com/openshift/cluster-monitoring-operator/pull/1198
    // Review hard anti-affinity changes and then we can add back PDB
    podDisruptionBudget:: {},
  }
