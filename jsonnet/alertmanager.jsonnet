local k = import 'ksonnet/ksonnet.beta.3/k.libsonnet';
local serviceAccount = k.core.v1.serviceAccount;
local service = k.core.v1.service;
local servicePort = k.core.v1.service.mixin.spec.portsType;
local secret = k.core.v1.secret;
local clusterRole = k.rbac.v1.clusterRole;
local policyRule = clusterRole.rulesType;

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
  alertmanager+:: {

    // OpenShift route to access the Alertmanager UI.

    route: {
      apiVersion: 'v1',
      kind: 'Route',
      metadata: {
        name: 'alertmanager-main',
        namespace: $._config.namespace,
      },
      spec: {
        to: {
          kind: 'Service',
          name: 'alertmanager-main',
        },
        port: {
          targetPort: 'web',
        },
        tls: {
          termination: 'Reencrypt',
        },
      },
    },

    // The ServiceAccount needs this annotation, to signify the identity
    // provider, that when a users it doing the oauth flow through the oauth
    // proxy, that it should redirect to the alertmanager-main route on
    // successful authentication.

    serviceAccount+:
      serviceAccount.mixin.metadata.withAnnotations({
        'serviceaccounts.openshift.io/oauth-redirectreference.alertmanager-main': '{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"alertmanager-main"}}',
      }),

    // Adding the serving certs annotation causes the serving certs controller
    // to generate a valid and signed serving certificate and put it in the
    // specified secret.
    //
    // The ClusterIP is explicitly set, as it signifies the
    // cluster-monitoring-operator, that when reconciling this service the
    // cluster IP needs to be retained.
    //
    // The ports are overridden, as due to the port binding of the oauth proxy
    // the serving port is 9094 instead of the 9093 default.

    service+:
      service.mixin.metadata.withAnnotations({
        'service.alpha.openshift.io/serving-cert-secret-name': 'alertmanager-main-tls',
      }) +
      service.mixin.spec.withType('ClusterIP') +
      service.mixin.spec.withPorts(servicePort.newNamed('web', 9094, 'web')),

    // The proxy secret is there to encrypt session created by the oauth proxy.

    proxySecret:
      secret.new('alertmanager-main-proxy', {}) +
      secret.mixin.metadata.withNamespace($._config.namespace) +
      secret.mixin.metadata.withLabels({ 'k8s-app': 'alertmanager-main' }),

    // In order for the oauth proxy to perform a TokenReview and
    // SubjectAccessReview for authN and authZ the alertmanager ServiceAccount
    // requires the `create` action on both of these.

    clusterRole:
      local rules = [authenticationRole, authorizationRole];

      clusterRole.new() +
      clusterRole.mixin.metadata.withName('alertmanager-main') +
      clusterRole.withRules(rules),
    clusterRoleBinding:
      local clusterRoleBinding = k.rbac.v1.clusterRoleBinding;

      clusterRoleBinding.new() +
      clusterRoleBinding.mixin.metadata.withName('alertmanager-main') +
      clusterRoleBinding.mixin.roleRef.withApiGroup('rbac.authorization.k8s.io') +
      clusterRoleBinding.mixin.roleRef.withName('alertmanager-main') +
      clusterRoleBinding.mixin.roleRef.mixinInstance({ kind: 'ClusterRole' }) +
      clusterRoleBinding.withSubjects([{ kind: 'ServiceAccount', name: 'alertmanager-main', namespace: $._config.namespace }]),

    // This changes the alertmanager to be scraped with TLS, authN and authZ,
    // which are not present in kube-prometheus.

    serviceMonitor+:
      {
        spec+: {
          endpoints: [
            {
              port: 'web',
              interval: '30s',
              scheme: 'https',
              tlsConfig: {
                caFile: '/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt',
                serverName: 'alertmanager-main',
              },
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            },
          ],
        },
      },

    // These patches inject the oauth proxy as a sidecar and configures it with
    // TLS.

    alertmanager+:
      {
        spec+: {
          securityContext: {},
          secrets: [
            'alertmanager-main-tls',
            'alertmanager-main-proxy',
          ],
          listenLocal: true,
          containers: [
            {
              name: 'alertmanager-proxy',
              image: $._config.imageRepos.openshiftOauthProxy + ':' + $._config.versions.openshiftOauthProxy,
              resources: {},
              ports: [
                {
                  containerPort: 9094,
                  name: 'web',
                },
              ],
              args: [
                '-provider=openshift',
                '-https-address=:9094',
                '-http-address=',
                '-email-domain=*',
                '-upstream=http://localhost:9093',
                '-openshift-sar={"resource": "namespaces", "verb": "get"}',
                '-openshift-delegate-urls={"/": {"resource": "namespaces", "verb": "get"}}',
                '-tls-cert=/etc/tls/private/tls.crt',
                '-tls-key=/etc/tls/private/tls.key',
                '-client-secret-file=/var/run/secrets/kubernetes.io/serviceaccount/token',
                '-cookie-secret-file=/etc/proxy/secrets/session_secret',
                '-openshift-service-account=alertmanager-main',
                '-openshift-ca=/etc/pki/tls/cert.pem',
                '-openshift-ca=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
                '-skip-auth-regex=^/metrics',
              ],
              volumeMounts: [
                {
                  mountPath: '/etc/tls/private',
                  name: 'secret-alertmanager-main-tls',
                },
                {
                  mountPath: '/etc/proxy/secrets',
                  name: 'secret-alertmanager-main-proxy',
                },
              ],
              env: [
                // Actual proxy settings will be modified at runtime.
                {
                  name: 'HTTP_PROXY',
                  value: '',
                },
                {
                  name: 'HTTPS_PROXY',
                  value: '',
                },
              ],
            },
          ],
        },
      },
  },
}
