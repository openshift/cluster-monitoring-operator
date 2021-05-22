local grafana = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/grafana.libsonnet';

function(params)
  local cfg = params;
  grafana(cfg) {

    consoleDashboardDefinitions: {
      apiVersion: 'v1',
      kind: 'ConfigMapList',
      items: std.map(
        function(d)
          d {
            metadata+: {
              namespace: 'openshift-config-managed',
              labels+: { 'console.openshift.io/dashboard': 'true' },
            },
          },
        $.dashboardDefinitions.items,
      ),
    },

    trustedCaBundle: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: {
        name: 'grafana-trusted-ca-bundle',
        namespace: cfg.namespace,
        labels: {
          'config.openshift.io/inject-trusted-cabundle': 'true',
        },
      },
      data: {
        'ca-bundle.crt': '',
      },
    },

    // OpenShift route to access the Grafana UI.
    route: {
      apiVersion: 'v1',
      kind: 'Route',
      metadata: {
        name: 'grafana',
        namespace: cfg.namespace,
      },
      spec: {
        to: {
          kind: 'Service',
          name: 'grafana',
        },
        port: {
          targetPort: 'https',
        },
        tls: {
          termination: 'Reencrypt',
          insecureEdgeTerminationPolicy: 'Redirect',
        },
      },
    },

    serviceMonitor+:
      {
        spec+: {
          endpoints: [
            {
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
              interval: '30s',
              port: 'https',
              scheme: 'https',
              tlsConfig: {
                caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                serverName: 'server-name-replaced-at-runtime',
              },
            },
          ],
        },
      },

    // The ServiceAccount needs this annotation, to signify the identity
    // provider, that when a users it doing the oauth flow through the oauth
    // proxy, that it should redirect to the grafana route on
    // successful authentication.
    serviceAccount+: {
      metadata+: {
        annotations+: {
          'serviceaccounts.openshift.io/oauth-redirectreference.grafana': '{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"grafana"}}',
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
    service+: {
      metadata+: {
        annotations: {
          'service.beta.openshift.io/serving-cert-secret-name': 'grafana-tls',
        },
      },
      spec+: {
        ports: [{
          name: 'https',
          port: 3000,
          targetPort: 'https',
        }],
        type: 'ClusterIP',
      },
    },

    // The proxy secret is there to encrypt session created by the oauth proxy.

    proxySecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'grafana-proxy',
        namespace: cfg.namespace,
        labels: { 'app.kubernetes.io/name': 'grafana' },
      },
      type: 'Opaque',
      data: {},
    },

    // In order for the oauth proxy to perform a TokenReview and
    // SubjectAccessReview for authN and authZ the Grafana ServiceAccount
    // requires the `create` action on both of these.

    clusterRole: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRole',
      metadata: {
        name: 'grafana',
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
        name: 'grafana',
      },
      roleRef: {
        apiGroup: 'rbac.authorization.k8s.io',
        kind: 'ClusterRole',
        name: 'grafana',
      },
      subjects: [{
        kind: 'ServiceAccount',
        name: 'grafana',
        namespace: cfg.namespace,
      }],
    },

    // These patches inject the oauth proxy as a sidecar and configures it with
    // TLS.

    deployment+: {
      spec+: {
        template+: {
          spec+: {
            containers: [
              super.containers[0] {
                args+: [
                  '-config=/etc/grafana/grafana.ini',
                ],
                ports: [{
                  name: 'http',
                  containerPort: 3001,
                }],
                readinessProbe:: null,
                resources+: {
                  requests+: {
                    cpu: '4m',
                    memory: '64Mi',
                  },
                },
              },
              {
                args: [
                  '-provider=openshift',
                  '-https-address=:3000',
                  '-http-address=',
                  '-email-domain=*',
                  '-upstream=http://localhost:3001',
                  '-openshift-sar={"resource": "namespaces", "verb": "get"}',
                  '-openshift-delegate-urls={"/": {"resource": "namespaces", "verb": "get"}}',
                  '-tls-cert=/etc/tls/private/tls.crt',
                  '-tls-key=/etc/tls/private/tls.key',
                  '-client-secret-file=/var/run/secrets/kubernetes.io/serviceaccount/token',
                  '-cookie-secret-file=/etc/proxy/secrets/session_secret',
                  '-openshift-service-account=grafana',
                  '-openshift-ca=/etc/pki/tls/cert.pem',
                  '-openshift-ca=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
                ],
                env: [
                  { name: 'HTTP_PROXY', value: '' },
                  { name: 'HTTPS_PROXY', value: '' },
                  { name: 'NO_PROXY', value: '' },
                ],
                image: 'quay.io/openshift/oauth-proxy:latest',  //FIXME(paulfantom)
                name: 'grafana-proxy',
                ports: [{
                  containerPort: 3000,
                  name: 'https',
                }],
                readinessProbe: {
                  httpGet: {
                    path: '/oauth/healthz',
                    port: 'https',
                    scheme: 'HTTPS',
                  },
                },
                resources: {
                  requests: { cpu: '1m', memory: '20Mi' },
                },
                volumeMounts: [
                  {
                    mountPath: '/etc/tls/private',
                    name: 'secret-grafana-tls',
                    readOnly: false,
                  },
                  {
                    mountPath: '/etc/proxy/secrets',
                    name: 'secret-grafana-proxy',
                    readOnly: false,
                  },
                ],
              },
            ],
            volumes+: [
              {
                name: 'secret-grafana-tls',
                secret: {
                  secretName: 'grafana-tls',
                },
              },
              {
                name: 'secret-grafana-proxy',
                secret: {
                  secretName: 'grafana-proxy',
                },
              },
            ],
            securityContext: {},
            priorityClassName: 'system-cluster-critical',
          },
        },
      },
    },
  }
