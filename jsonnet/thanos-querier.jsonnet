local k = import 'ksonnet/ksonnet.beta.4/k.libsonnet';
local secret = k.core.v1.secret;
local service = k.core.v1.service;
local ports = service.mixin.spec.portsType;
local deployment = k.apps.v1.deployment;
local container = deployment.mixin.spec.template.spec.containersType;
local volume = deployment.mixin.spec.template.spec.volumesType;
local clusterRole = k.rbac.v1.clusterRole;
local policyRule = clusterRole.rulesType;
local configmap = k.core.v1.configMap;

local authenticationRole =
  policyRule.new() +
  policyRule.withApiGroups(['authentication.k8s.io']) +
  policyRule.withResources([
    'tokenreviews',
  ]) +
  policyRule.withVerbs(['create']);

local authorizationRole =
  policyRule.new() +
  policyRule.withApiGroups(['authorization.k8s.io']) +
  policyRule.withResources([
    'subjectaccessreviews',
  ]) +
  policyRule.withVerbs(['create']);

{
  local config = super._config,

  thanos+:: {
    image:: config.imageRepos.openshiftThanos + ':' + config.versions.openshiftThanos,

    querier+: {
      trustedCaBundle:
        configmap.new('thanos-querier-trusted-ca-bundle', { 'ca-bundle.crt': '' }) +
        configmap.mixin.metadata.withNamespace($._config.namespace) +
        configmap.mixin.metadata.withLabels({ 'config.openshift.io/inject-trusted-cabundle': 'true' }),

      route: {
        apiVersion: 'v1',
        kind: 'Route',
        metadata: {
          name: 'thanos-querier',
          namespace: $._config.namespace,
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

      clusterRole:
        clusterRole.new() +
        clusterRole.mixin.metadata.withName('thanos-querier') +
        clusterRole.withRules([authenticationRole, authorizationRole]),

      clusterRoleBinding:
        local clusterRoleBinding = k.rbac.v1.clusterRoleBinding;

        clusterRoleBinding.new() +
        clusterRoleBinding.mixin.metadata.withName('thanos-querier') +
        clusterRoleBinding.mixin.roleRef.withApiGroup('rbac.authorization.k8s.io') +
        clusterRoleBinding.mixin.roleRef.withName('thanos-querier') +
        clusterRoleBinding.mixin.roleRef.mixinInstance({ kind: 'ClusterRole' }) +
        clusterRoleBinding.withSubjects([{
          kind: 'ServiceAccount',
          name: 'thanos-querier',
          namespace: $._config.namespace,
        }]),

      grpcTlsSecret:
        secret.new('thanos-querier-grpc-tls', {}) +
        secret.mixin.metadata.withNamespace($._config.namespace) +
        secret.mixin.metadata.withLabels({ 'k8s-app': 'thanos-querier' }),

      // holds the secret which is used encrypt/decrypt cookies
      // issued by the oauth proxy.
      oauthCookieSecret:
        secret.new('thanos-querier-oauth-cookie', {}) +
        secret.mixin.metadata.withNamespace($._config.namespace) +
        secret.mixin.metadata.withLabels({ 'k8s-app': 'thanos-querier' }),

      // holds the htpasswd configuration
      // which includes a static secret used to authenticate/authorize
      // requests originating from grafana.
      oauthHtpasswdSecret:
        secret.new('thanos-querier-oauth-htpasswd', {}) +
        secret.mixin.metadata.withNamespace($._config.namespace) +
        secret.mixin.metadata.withLabels({ 'k8s-app': 'thanos-querier' }),

      // holds the kube-rbac-proxy configuration as a secret.
      // It configures to template the request in flight
      // to extract a "namespace" query parameter
      // and perform a SubjectAccessReview
      // asserting if the request bearer token in flight has permissions
      // to access the pod.metrics.k8s.io API.
      // The asserted verb (PUT, GET, POST, etc.) is implied from the http request verb in flight.
      kubeRbacProxySecret:
        local config = {
          'config.yaml': std.base64(std.manifestYamlDoc({
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
          })),
        };

        secret.new('thanos-querier-kube-rbac-proxy', config) +
        secret.mixin.metadata.withNamespace($._config.namespace) +
        secret.mixin.metadata.withLabels({ 'k8s-app': 'thanos' }),

      serviceAccount:
        local serviceAccount = k.core.v1.serviceAccount;

        serviceAccount.new('thanos-querier') +
        serviceAccount.mixin.metadata.withNamespace($._config.namespace) +

        // The ServiceAccount needs this annotation, to signify the identity
        // provider, that when a users it doing the oauth flow through the
        // oauth proxy, that it should redirect to the thanos-querier route on
        // successful authentication.
        serviceAccount.mixin.metadata.withAnnotations({
          'serviceaccounts.openshift.io/oauth-redirectreference.thanos-querier': '{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"thanos-querier"}}',
        }),

      service+:
        // The following annotation will instruct the serving certs controller
        // to synthesize the "thanos-querier-tls" secret.
        // Hence, we don't need to declare that secret explicitly.
        service.mixin.metadata.withAnnotations({
          'service.alpha.openshift.io/serving-cert-secret-name': 'thanos-querier-tls',
        }) +
        service.mixin.metadata.withNamespace(config.namespace) +
        // The ClusterIP is explicitly set, as it signifies the
        // cluster-monitoring-operator, that when reconciling this service the
        // cluster IP needs to be retained.
        service.mixin.spec.withType('ClusterIP') +
        service.mixin.spec.withPorts([
          ports.newNamed('web', 9091, 'web'),
          ports.newNamed('tenancy', 9092, 'tenancy'),
        ]),

      deployment+:
        deployment.mixin.metadata.withNamespace(config.namespace) +
        {
          spec+: {
            replicas: 2,
            template+: {
              spec+: {
                volumes: [
                  volume.fromSecret('secret-thanos-querier-tls', 'thanos-querier-tls'),
                  volume.fromSecret('secret-thanos-querier-oauth-cookie', 'thanos-querier-oauth-cookie'),
                  volume.fromSecret('secret-thanos-querier-oauth-htpasswd', 'thanos-querier-oauth-htpasswd'),
                  volume.fromSecret('secret-thanos-querier-kube-rbac-proxy', 'thanos-querier-kube-rbac-proxy'),
                ],
                serviceAccountName: 'thanos-querier',
                securityContext: {},
                priorityClassName: 'system-cluster-critical',
                tolerations: [
                  {
                    key: 'node-role.kubernetes.io/master',
                    operator: 'Exists',
                    effect: 'NoSchedule',
                  },
                ],
                containers: [
                  super.containers[0] {
                    livenessProbe: {
                      httpGet:: {},
                      exec: {
                        command: ['sh', '-c', 'curl http://localhost:9090/-/healthy'],
                      },
                    },
                    readinessProbe: {
                      httpGet:: {},
                      exec: {
                        command: ['sh', '-c', 'curl http://localhost:9090/-/healthy'],
                      },
                    },
                    args: [
                      'query',
                      '--query.replica-label=prometheus_replica',
                      '--grpc-address=127.0.0.1:10901',
                      '--http-address=127.0.0.1:9090',
                      '--grpc-client-tls-secure',
                      '--grpc-client-tls-cert=/etc/tls/grpc/client.crt',
                      '--grpc-client-tls-key=/etc/tls/grpc/client.key',
                      '--grpc-client-tls-ca=/etc/tls/grpc/ca.crt',
                      '--grpc-client-server-name=prometheus-grpc',
                      '--store=dnssrv+_grpc._tcp.%s.%s.svc.cluster.local' % [
                        'prometheus-operated',
                        'openshift-monitoring',
                      ],
                    ],
                    resources: {
                      requests: {
                        memory: '12Mi',
                        cpu: '10m',
                      },
                    },
                    ports+:: {},
                    volumeMounts: [
                      {
                        mountPath: '/etc/tls/grpc',
                        name: 'secret-grpc-tls',
                      },
                    ],
                  },
                  {
                    name: 'oauth-proxy',
                    image: $._config.imageRepos.openshiftOauthProxy + ':' + $._config.versions.openshiftOauthProxy,
                    resources: {
                      requests: {
                        memory: '20Mi',
                        cpu: '10m',
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
                      '-openshift-service-account=thanos-querier',
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
                    image: $._config.imageRepos.kubeRbacProxy + ':' + $._config.versions.kubeRbacProxy,
                    resources: {
                      requests: {
                        memory: '20Mi',
                        cpu: '10m',
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
                    ],
                    terminationMessagePolicy: 'FallbackToLogsOnError',
                    volumeMounts: [
                      {
                        mountPath: '/etc/tls/private',
                        name: 'secret-thanos-querier-tls',
                      },
                      {
                        mountPath: '/etc/kube-rbac-proxy',
                        name: 'secret-' + $.thanos.querier.kubeRbacProxySecret.metadata.name,
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
                        cpu: '10m',
                      },
                    },
                    terminationMessagePolicy: 'FallbackToLogsOnError',
                  },
                ],
              },
            },
          },
        },
    },
  },
}
