{
  _config+:: {
    grafana+:: {
      datasources: [{
        name: 'prometheus',
        type: 'prometheus',
        access: 'proxy',
        orgId: 1,
        url: 'https://prometheus-k8s.openshift-monitoring.svc:9091',
        version: 1,
        editable: false,
        basicAuth: true,
        basicAuthUser: 'internal',
        basicAuthPassword: '',
        jsonData: {
          tlsSkipVerify: true,
        },
      }],

      config: {
        sections: {
          paths: {
            data: '/var/lib/grafana',
            logs: '/var/lib/grafana/logs',
            plugins: '/var/lib/grafana/plugins',
            provisioning: '/etc/grafana/provisioning',
          },
          server: {
            http_addr: '127.0.0.1',
            http_port: '3001',
          },
          security: {
            // OpenShift users are limited to 63 characters, with this we are
            // setting the Grafana user to something that can never be created
            // in OpenShift. This prevents users from getting proxied with an
            // identity that has superuser permissions in Grafana.
            admin_user: 'WHAT_YOU_ARE_DOING_IS_VOIDING_SUPPORT_0000000000000000000000000000000000000000000000000000000000000000',
            cookie_secure: true,
          },
          auth: {
            disable_login_form: true,
            disable_signout_menu: true,
          },
          'auth.basic': {
            enabled: false,
          },
          'auth.proxy': {
            enabled: true,
            header_name: 'X-Forwarded-User',
            auto_sign_up: true,
          },
          analytics: {
            reporting_enabled: false,
            check_for_updates: false,
          },
        },
      },
    },
  },

  grafana+:: {
    local dashboards = super.dashboardDefinitions.items,
    dashboardDefinitions: {
      apiVersion: 'v1',
      kind: 'ConfigMapList',
      items: dashboards,
    },
    consoleDashboardDefinitions: {
      apiVersion: 'v1',
      kind: 'ConfigMapList',
      items: std.map(
        function(c)
          c {
            metadata+: {
              namespace: 'openshift-config-managed',
              labels+: { 'console.openshift.io/dashboard': 'true' },
            },
          },
        dashboards
      ),
    },

    trustedCaBundle: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: {
        name: 'grafana-trusted-ca-bundle',
        namespace: $._config.namespace,
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
        namespace: $._config.namespace,
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
        namespace: $._config.namespace,
        labels: { 'k8s-app': 'grafana' },
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
        namespace: $._config.namespace,
      }],
    },

    // These patches inject the oauth proxy as a sidecar and configures it with
    // TLS.

    deployment+:
      {
        spec+: {
          template+: {
            spec+: {
              containers: [
                super.containers[0] {
                  ports: [{
                    name: 'http',
                    containerPort: 3001,
                  }],
                  readinessProbe:: null,
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
                    '-skip-auth-regex=^/metrics',
                  ],
                  env: [
                    { name: 'HTTP_PROXY', value: '' },
                    { name: 'HTTPS_PROXY', value: '' },
                    { name: 'NO_PROXY', value: '' },
                  ],
                  image: $._config.imageRepos.openshiftOauthProxy + ':' + $._config.versions.openshiftOauthProxy,
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
      } + {
        spec+: {
          template+: {
            spec+: {
              containers:
                std.map(
                  function(c)
                    if c.name == 'grafana' then
                      c {
                        resources+: {
                          requests+: {
                            cpu: '4m',
                          },
                        },
                        args+: [
                          '-config=/etc/grafana/grafana.ini',
                        ],
                      }
                    else
                      c,
                  super.containers,
                ),
            },
          },
        },
      },
  },
}
