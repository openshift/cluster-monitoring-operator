local querier = import 'kube-thanos/kube-thanos-query.libsonnet';

function(params)
  local cfg = params;
  local tq = querier(cfg);
  tq {
    mixin:: (import 'github.com/thanos-io/thanos/mixin/alerts/query.libsonnet') {
      query+:: {
        selector: 'job="thanos-querier"',
      },
    },

    prometheusRule: {
      apiVersion: 'monitoring.coreos.com/v1',
      kind: 'PrometheusRule',
      metadata: {
        name: 'thanos-querier',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
      },
      spec: $.mixin.prometheusAlerts,
    },

    trustedCaBundle: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: {
        name: 'thanos-querier-trusted-ca-bundle',
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
        name: 'thanos-querier',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
      },
      spec: {
        to: {
          kind: 'Service',
          name: 'thanos-querier',
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
        name: 'thanos-querier',
        labels: tq.config.commonLabels,
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
      ],
    },

    clusterRoleBinding: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRoleBinding',
      metadata: {
        name: 'thanos-querier',
        labels: tq.config.commonLabels,
      },
      roleRef: {
        apiGroup: 'rbac.authorization.k8s.io',
        kind: 'ClusterRole',
        name: 'thanos-querier',
      },
      subjects: [{
        kind: 'ServiceAccount',
        name: 'thanos-querier',
        namespace: cfg.namespace,
      }],
    },

    grpcTlsSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'thanos-querier-grpc-tls',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
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
        name: 'thanos-querier-oauth-cookie',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
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
        name: 'thanos-querier-oauth-htpasswd',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
      },
      type: 'Opaque',
      data: {},
    },

    // holds the kube-rbac-proxy configuration as a secret.
    // It configures to template the request in flight
    // to extract a "namespace" query parameter
    // and perform a SubjectAccessReview
    // asserting if the request bearer token in flight has permissions
    // to access the pod.metrics.k8s.io API.
    // The asserted verb (PUT, GET, POST, etc.) is implied from the http request verb in flight.
    kubeRbacProxySecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'thanos-querier-kube-rbac-proxy',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
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

    // Same as kubeRbacProxySecret but performs a SubjectAccessReview
    // asserting if the request bearer token in flight has permissions
    // to access the prometheusrules.monitoring.coreos.com API.
    kubeRbacProxyRulesSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'thanos-querier-kube-rbac-proxy-rules',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
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
              apiGroup: 'monitoring.coreos.com',
              resource: 'prometheusrules',
              namespace: '{{ .Value }}',
            },
          },
        }),
      },
    },

    serviceAccount: {
      apiVersion: 'v1',
      kind: 'ServiceAccount',
      metadata: {
        name: 'thanos-querier',
        namespace: cfg.namespace,
        labels: tq.config.commonLabels,
        annotations: {
          'serviceaccounts.openshift.io/oauth-redirectreference.thanos-querier': '{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"thanos-querier"}}',
        },
      },
    },

    service+: {
      apiVersion: 'v1',
      kind: 'Service',
      metadata+: {
        annotations: {
          'service.beta.openshift.io/serving-cert-secret-name': 'thanos-querier-tls',
        },
        labels: tq.config.commonLabels,
      },
      spec+: {
        ports: [{
          name: 'web',
          port: 9091,
          targetPort: 'web',
        }, {
          name: 'tenancy',
          port: 9092,
          targetPort: 'tenancy',
        }, {
          name: 'tenancy-rules',
          port: 9093,
          targetPort: 'tenancy-rules',
        }],
        type: 'ClusterIP',
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
              },
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            },
          ],
        },
      },

    deployment+: {
      spec+: {
        strategy+: {
          // Apply HA conventions
          rollingUpdate: {
            maxUnavailable: 1,
          },
        },
        template+: {
          spec+: {
            // TODO(dgrisonnet): remove once the upstream anti-affinity addon
            // can be extended.
            affinity+: {
              podAntiAffinity: {
                // Apply HA conventions
                requiredDuringSchedulingIgnoredDuringExecution: [
                  {
                    labelSelector: {
                      matchLabels: tq.config.podLabelSelector,
                    },
                    topologyKey: 'kubernetes.io/hostname',
                  },
                ],
              },
            },
            volumes+: [
              {
                name: 'secret-thanos-querier-tls',
                secret: {
                  secretName: 'thanos-querier-tls',
                },
              },
              {
                name: 'secret-thanos-querier-oauth-cookie',
                secret: {
                  secretName: 'thanos-querier-oauth-cookie',
                },
              },
              {
                name: 'secret-thanos-querier-oauth-htpasswd',
                secret: {
                  secretName: 'thanos-querier-oauth-htpasswd',
                },
              },
              {
                name: 'secret-thanos-querier-kube-rbac-proxy',
                secret: {
                  secretName: 'thanos-querier-kube-rbac-proxy',
                },
              },
              {
                name: 'secret-thanos-querier-kube-rbac-proxy-rules',
                secret: {
                  secretName: 'thanos-querier-kube-rbac-proxy-rules',
                },
              },
            ],
            serviceAccountName: 'thanos-querier',
            priorityClassName: 'system-cluster-critical',
            containers: [
              super.containers[0] {
                livenessProbe: {
                  httpGet:: {},
                  exec: {
                    command: ['sh', '-c', 'if [ -x "$(command -v curl)" ]; then exec curl http://localhost:9090/-/healthy; elif [ -x "$(command -v wget)" ]; then exec wget --quiet --tries=1 --spider http://localhost:9090/-/healthy; else exit 1; fi'],
                  },
                },
                readinessProbe: {
                  httpGet:: {},
                  exec: {
                    command: ['sh', '-c', 'if [ -x "$(command -v curl)" ]; then exec curl http://localhost:9090/-/ready; elif [ -x "$(command -v wget)" ]; then exec wget --quiet --tries=1 --spider http://localhost:9090/-/ready; else exit 1; fi'],
                  },
                },
                args: std.map(
                  function(a)
                    if std.startsWith(a, '--grpc-address=') then '--grpc-address=127.0.0.1:10901'
                    else if std.startsWith(a, '--http-address=') then '--http-address=127.0.0.1:9090'
                    else a,
                  std.filter(function(a) !std.startsWith(a, '--log.level='), super.args)
                ) + [
                  '--store.sd-dns-resolver=miekgdns',
                  '--grpc-client-tls-secure',
                  '--grpc-client-tls-cert=/etc/tls/grpc/client.crt',
                  '--grpc-client-tls-key=/etc/tls/grpc/client.key',
                  '--grpc-client-tls-ca=/etc/tls/grpc/ca.crt',
                  '--grpc-client-server-name=prometheus-grpc',
                  '--rule=dnssrv+_grpc._tcp.prometheus-operated.openshift-monitoring.svc.cluster.local',
                ],
                resources: {
                  requests: {
                    memory: '12Mi',
                    cpu: '10m',
                  },
                },
                ports: [
                  {
                    containerPort: 9090,
                    name: 'http',
                  },
                ],
                volumeMounts+: [
                  {
                    mountPath: '/etc/tls/grpc',
                    name: 'secret-grpc-tls',
                  },
                ],
              },
              {
                name: 'oauth-proxy',
                image: 'quay.io/openshift/oauth-proxy:latest',  //FIXME(paulfantom)
                resources: {
                  requests: {
                    memory: '20Mi',
                    cpu: '1m',
                  },
                },
                ports: [{
                  containerPort: 9091,
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
                  '-upstream=http://localhost:9090',
                  '-htpasswd-file=/etc/proxy/htpasswd/auth',
                  '-openshift-service-account=thanos-querier',
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
                  {
                    mountPath: '/etc/tls/private',
                    name: 'secret-thanos-querier-tls',
                  },
                  {
                    mountPath: '/etc/proxy/secrets',
                    name: 'secret-thanos-querier-oauth-cookie',
                  },
                  {
                    mountPath: '/etc/proxy/htpasswd',
                    name: 'secret-thanos-querier-oauth-htpasswd',
                  },
                ],
              },
              {
                name: 'kube-rbac-proxy',
                image: 'quay.io/coreos/kube-rbac-proxy:v0.8.0',  //FIXME(paulfantom)
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
                  '--tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305',  //FIXME(paulfantom)
                  '--logtostderr=true',
                  '--allow-paths=/api/v1/query,/api/v1/query_range',
                ],
                terminationMessagePolicy: 'FallbackToLogsOnError',
                volumeMounts: [
                  {
                    mountPath: '/etc/tls/private',
                    name: 'secret-thanos-querier-tls',
                  },
                  {
                    mountPath: '/etc/kube-rbac-proxy',
                    name: 'secret-' + $.kubeRbacProxySecret.metadata.name,
                  },
                ],
              },
              {
                name: 'prom-label-proxy',
                image: 'quay.io/coreos/prom-label-proxy:v0.2.0',  // FIXME(paulfantom)
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
                name: 'kube-rbac-proxy-rules',
                image: 'quay.io/coreos/kube-rbac-proxy:v0.8.0',  //FIXME(paulfantom)
                resources: {
                  requests: {
                    memory: '15Mi',
                    cpu: '1m',
                  },
                },
                ports: [
                  {
                    containerPort: 9093,
                    name: 'tenancy-rules',
                  },
                ],
                args: [
                  '--secure-listen-address=0.0.0.0:9093',
                  '--upstream=http://127.0.0.1:9095',
                  '--config-file=/etc/kube-rbac-proxy/config.yaml',
                  '--tls-cert-file=/etc/tls/private/tls.crt',
                  '--tls-private-key-file=/etc/tls/private/tls.key',
                  '--tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305',  //FIXME(paulfantom)
                  '--logtostderr=true',
                  '--allow-paths=/api/v1/rules',
                ],
                terminationMessagePolicy: 'FallbackToLogsOnError',
                volumeMounts: [
                  {
                    mountPath: '/etc/tls/private',
                    name: 'secret-thanos-querier-tls',
                  },
                  {
                    mountPath: '/etc/kube-rbac-proxy',
                    name: 'secret-' + $.kubeRbacProxyRulesSecret.metadata.name,
                  },
                ],
              },
            ],
          },
        },
      },
    },
  }
