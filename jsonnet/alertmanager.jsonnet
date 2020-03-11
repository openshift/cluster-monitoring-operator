local k = import 'ksonnet/ksonnet.beta.3/k.libsonnet';
local serviceAccount = k.core.v1.serviceAccount;
local service = k.core.v1.service;
local servicePort = k.core.v1.service.mixin.spec.portsType;
local secret = k.core.v1.secret;
local configmap = k.core.v1.configMap;
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

    trustedCaBundle:
      configmap.new('alertmanager-trusted-ca-bundle', { 'ca-bundle.crt': '' }) +
      configmap.mixin.metadata.withNamespace($._config.namespace) +
      configmap.mixin.metadata.withLabels({ 'config.openshift.io/inject-trusted-cabundle': 'true' }),

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
          insecureEdgeTerminationPolicy: 'Redirect',
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
      service.mixin.spec.withPorts([
        servicePort.newNamed('web', 9094, 'web'),
        servicePort.newNamed('tenancy', 9092, 'tenancy'),
      ]),

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

    kubeRbacProxySecret:
      local config = {
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
      };

      secret.fromString('alertmanager-kube-rbac-proxy', config) +
      secret.mixin.metadata.withNamespace($._config.namespace) +
      secret.mixin.metadata.withLabels({ 'k8s-app': 'alertmanager-main' }),

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
                caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
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
          priorityClassName: 'system-cluster-critical',
          secrets: [
            'alertmanager-main-tls',
            'alertmanager-main-proxy',
            $.alertmanager.kubeRbacProxySecret.metadata.name,
          ],
          listenLocal: true,
          resources: {
            requests: {
              cpu: '4m',
            },
          },
          containers: [
            {
              name: 'alertmanager-proxy',
              image: $._config.imageRepos.openshiftOauthProxy + ':' + $._config.versions.openshiftOauthProxy,
              ports: [
                {
                  containerPort: 9095,
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
                '-https-address=:9095',
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
              terminationMessagePolicy: 'FallbackToLogsOnError',
              resources: {
                requests: {
                  cpu: '1m',
                  memory: '20Mi',
                },
              },
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
            },
            {
              name: 'kube-rbac-proxy',
              image: $._config.imageRepos.kubeRbacProxy + ':' + $._config.versions.kubeRbacProxy,
              resources: {
                requests: {
                  cpu: '1m',
                  memory: '20Mi',
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
                '--tls-cipher-suites=' + std.join(',', $._config.tlsCipherSuites),
                '--logtostderr=true',
                '--v=10',
              ],
              terminationMessagePolicy: 'FallbackToLogsOnError',
              volumeMounts: [
                {
                  mountPath: '/etc/kube-rbac-proxy',
                  name: 'secret-' + $.alertmanager.kubeRbacProxySecret.metadata.name,
                },
                {
                  mountPath: '/etc/tls/private',
                  name: 'secret-alertmanager-main-tls',
                },
              ],
            },
            {
              name: 'prom-label-proxy',
              image: $._config.imageRepos.promLabelProxy + ':' + $._config.versions.promLabelProxy,
              args: [
                '--insecure-listen-address=127.0.0.1:9096',
                '--upstream=http://127.0.0.1:9093',
                '--label=namespace',
              ],
              resources: {
                requests: {
                  cpu: '1m',
                  memory: '20Mi',
                },
              },
              terminationMessagePolicy: 'FallbackToLogsOnError',
            },
          ],
        },
      },
  },
}
