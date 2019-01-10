local k = import 'ksonnet/ksonnet.beta.3/k.libsonnet';
local serviceAccount = k.core.v1.serviceAccount;
local service = k.core.v1.service;
local servicePort = k.core.v1.service.mixin.spec.portsType;
local secret = k.core.v1.secret;
local configmap = k.core.v1.configMap;
local clusterRole = k.rbac.v1.clusterRole;
local policyRule = clusterRole.rulesType;

local deployment = k.apps.v1beta2.deployment;
local container = deployment.mixin.spec.template.spec.containersType;
local volume = deployment.mixin.spec.template.spec.volumesType;
local containerPort = container.portsType;
local containerVolumeMount = container.volumeMountsType;

local authenticationRole = policyRule.new() +
                           policyRule.withApiGroups(['authentication.k8s.io']) +
                           policyRule.withResources([
                             'tokenreviews',
                           ]) +
                           policyRule.withVerbs(['create']);

local authorizationRole = policyRule.new() +
                          policyRule.withApiGroups(['authorization.k8s.io']) +
                          policyRule.withResources([
                            'subjectaccessreviews',
                          ]) +
                          policyRule.withVerbs(['create']);

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
        },
      },
    },
  },

  grafana+:: {

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
    // proxy, that it should redirect to the alertmanager-main route on
    // successful authentication.

    serviceAccount+:
      serviceAccount.mixin.metadata.withAnnotations({
        'serviceaccounts.openshift.io/oauth-redirectreference.grafana': '{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"grafana"}}',
      }),

    // Adding the serving certs annotation causes the serving certs controller
    // to generate a valid and signed serving certificate and put it in the
    // specified secret.
    //
    // The ClusterIP is explicitly set, as it signifies the
    // cluster-monitoring-operator, that when reconciling this service the
    // cluster IP needs to be retained.

    service+:
      service.mixin.metadata.withAnnotations({
        'service.alpha.openshift.io/serving-cert-secret-name': 'grafana-tls',
      }) +
      service.mixin.spec.withType('ClusterIP') +
      service.mixin.spec.withPorts(servicePort.newNamed('https', 3000, 'https')),

    // The proxy secret is there to encrypt session created by the oauth proxy.

    proxySecret:
      secret.new('grafana-proxy', {}) +
      secret.mixin.metadata.withNamespace($._config.namespace) +
      secret.mixin.metadata.withLabels({ 'k8s-app': 'grafana' }),

    // In order for the oauth proxy to perform a TokenReview and
    // SubjectAccessReview for authN and authZ the Grafana ServiceAccount
    // requires the `create` action on both of these.

    clusterRole:
      local rules = [authenticationRole, authorizationRole];

      clusterRole.new() +
      clusterRole.mixin.metadata.withName('grafana') +
      clusterRole.withRules(rules),
    clusterRoleBinding:
      local clusterRoleBinding = k.rbac.v1.clusterRoleBinding;

      clusterRoleBinding.new() +
      clusterRoleBinding.mixin.metadata.withName('grafana') +
      clusterRoleBinding.mixin.roleRef.withApiGroup('rbac.authorization.k8s.io') +
      clusterRoleBinding.mixin.roleRef.withName('grafana') +
      clusterRoleBinding.mixin.roleRef.mixinInstance({ kind: 'ClusterRole' }) +
      clusterRoleBinding.withSubjects([{ kind: 'ServiceAccount', name: 'grafana', namespace: $._config.namespace }]),

    // These patches inject the oauth proxy as a sidecar and configures it with
    // TLS.

    deployment+:
      {
        spec+: {
          template+: {
            spec+: {
              containers: [
                super.containers[0] +
                container.withPorts(containerPort.newNamed('http', 3001)) +
                {
                  readinessProbe:: null,
                },
                container.new('grafana-proxy', $._config.imageRepos.openshiftOauthProxy + ':' + $._config.versions.openshiftOauthProxy) +
                container.mixin.readinessProbe.tcpSocket.withPort('https') +
                container.withArgs([
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
                ]) +
                container.withPorts(containerPort.newNamed('https', 3000)) +
                container.withVolumeMounts([
                  containerVolumeMount.new('secret-grafana-tls', '/etc/tls/private'),
                  containerVolumeMount.new('secret-grafana-proxy', '/etc/proxy/secrets'),
                ]),
              ],
              volumes+: [
                volume.fromSecret('secret-grafana-tls', 'grafana-tls'),
                volume.fromSecret('secret-grafana-proxy', 'grafana-proxy'),
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
