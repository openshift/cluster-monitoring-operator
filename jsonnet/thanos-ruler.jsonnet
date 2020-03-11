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
  local thanosRulerName = 'user-workload',
  local thanosRulerConfig = super._config +
  {
    name: thanosRulerName,
    namespace: 'openshift-user-workload-monitoring',
    labels: {
      'app.kubernetes.io/name': thanosRulerName,
    },
    selectorLabels: {
      'app': 'thanos-ruler',
      'thanos-ruler': thanosRulerName,
    },
    ports: {
      grpc: 10901,
      http: 10902,
    },

  },

  thanos+:: {
    image:: thanosRulerConfig.imageRepos.openshiftThanos + ':' + thanosRulerConfig.versions.openshiftThanos,

    ruler+: {

      trustedCaBundle:
        configmap.new('thanos-ruler-trusted-ca-bundle', { 'ca-bundle.crt': '' }) +
        configmap.mixin.metadata.withNamespace(thanosRulerConfig.namespace) +
        configmap.mixin.metadata.withLabels({ 'config.openshift.io/inject-trusted-cabundle': 'true' }),

      route: {
        apiVersion: 'v1',
        kind: 'Route',
        metadata: {
          name: 'thanos-ruler',
          namespace: thanosRulerConfig.namespace,
        },
        spec: {
          to: {
            kind: 'Service',
            name: 'thanos-ruler',
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
        clusterRole.mixin.metadata.withName('thanos-ruler') +
        clusterRole.withRules([authenticationRole, authorizationRole]),

      clusterRoleBinding:
        local clusterRoleBinding = k.rbac.v1.clusterRoleBinding;

        clusterRoleBinding.new() +
        clusterRoleBinding.mixin.metadata.withName('thanos-ruler') +
        clusterRoleBinding.mixin.roleRef.withApiGroup('rbac.authorization.k8s.io') +
        clusterRoleBinding.mixin.roleRef.withName('thanos-ruler') +
        clusterRoleBinding.mixin.roleRef.mixinInstance({ kind: 'ClusterRole' }) +
        clusterRoleBinding.withSubjects([{
          kind: 'ServiceAccount',
          name: 'thanos-ruler',
          namespace: thanosRulerConfig.namespace,
        }]),

      grpcTlsSecret:
        secret.new('thanos-ruler-grpc-tls', {}) +
        secret.mixin.metadata.withNamespace(thanosRulerConfig.namespace) +
        secret.mixin.metadata.withLabels({ 'k8s-app': 'thanos-ruler' }),

      // holds the secret which is used encrypt/decrypt cookies
      // issued by the oauth proxy.
      oauthCookieSecret:
        secret.new('thanos-ruler-oauth-cookie', {}) +
        secret.mixin.metadata.withNamespace(thanosRulerConfig.namespace) +
        secret.mixin.metadata.withLabels({ 'k8s-app': 'thanos-ruler' }),

      // holds the htpasswd configuration
      // which includes a static secret used to authenticate/authorize
      // requests originating from grafana.
      oauthHtpasswdSecret:
        secret.new('thanos-ruler-oauth-htpasswd', {}) +
        secret.mixin.metadata.withNamespace(thanosRulerConfig.namespace) +
        secret.mixin.metadata.withLabels({ 'k8s-app': 'thanos-ruler' }),

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

        secret.new('thanos-ruler-kube-rbac-proxy', config) +
        secret.mixin.metadata.withNamespace(thanosRulerConfig.namespace) +
        secret.mixin.metadata.withLabels({ 'k8s-app': 'thanos' }),

      serviceAccount:
        local serviceAccount = k.core.v1.serviceAccount;

        serviceAccount.new('thanos-ruler') +
        serviceAccount.mixin.metadata.withNamespace(thanosRulerConfig.namespace) +

        // The ServiceAccount needs this annotation, to signify the identity
        // provider, that when a users it doing the oauth flow through the
        // oauth proxy, that it should redirect to the thanos-ruler route on
        // successful authentication.
        serviceAccount.mixin.metadata.withAnnotations({
          'serviceaccounts.openshift.io/oauth-redirectreference.thanos-ruler': '{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"thanos-ruler"}}',
        }),

      service:
        service.new(
          'thanos-ruler-' + thanosRulerConfig.name,
          thanosRulerConfig.selectorLabels,
          [
            ports.newNamed('grpc', thanosRulerConfig.ports.grpc, 'grpc'),
            ports.newNamed('http', thanosRulerConfig.ports.http, 'http'),
          ],
        ) +
        // The following annotation will instruct the serving certs controller
        // to synthesize the "thanos-ruler-tls" secret.
        // Hence, we don't need to declare that secret explicitly.
        service.mixin.metadata.withAnnotations({
          'service.alpha.openshift.io/serving-cert-secret-name': 'thanos-ruler-tls',
        }) +
        service.mixin.metadata.withLabels(thanosRulerConfig.labels) +
        service.mixin.metadata.withNamespace(thanosRulerConfig.namespace) +
        // The ClusterIP is explicitly set, as it signifies the
        // cluster-monitoring-operator, that when reconciling this service the
        // cluster IP needs to be retained.
        service.mixin.spec.withType('ClusterIP') +
        service.mixin.spec.withSessionAffinity('ClientIP') +
        service.mixin.spec.withPorts([
          ports.newNamed('web', 9091, 'web'),
        ]),

      serviceMonitor: {
        apiVersion: 'monitoring.coreos.com/v1',
        kind: 'ServiceMonitor',
        metadata: {
          name: 'thanos-ruler',
          namespace: thanosRulerConfig.namespace,
          labels: {
            'k8s-app': 'alertmanager',
          },
        },
        spec: {
          selector: {
            matchLabels: {
              thanosRuler: thanosRulerConfig.name,
            },
          },
          endpoints: [
            {
              port: 'web',
              interval: '30s',
              tlsConfig: {
                caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                serverName: 'server-name-replaced-at-runtime',
              },
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            },
          ],
        },
      },

      thanosRuler: {
        apiVersion: 'monitoring.coreos.com/v1',
        kind: 'ThanosRuler',
        metadata: {
          name: thanosRulerConfig.name,
          namespace: thanosRulerConfig.namespace,
          labels: {
            thanosRulerName: thanosRulerConfig.name,
          },
        },
        spec: {
          replicas: 2,
          image: $._config.imageRepos.openshiftThanos + ':' + $._config.versions.openshiftThanos,
          ruleSelector: {
            matchLabels: {
              role: 'thanos-rules',
            },
          },
          queryEndpoints: [
            'dnssrv+_web._tcp.thanos-querier.openshift-monitoring.svc.cluster.local'
          ],
          alertmanagersUrl: [
            'dnssrv+_web._tcp.alertmanager-main.openshift-monitoring.svc.cluster.local',
          ],
          volumes: [
            volume.fromSecret('secret-thanos-ruler-tls', 'thanos-ruler-tls'),
            volume.fromSecret('secret-thanos-ruler-oauth-cookie', 'thanos-ruler-oauth-cookie'),
            volume.fromSecret('secret-thanos-ruler-oauth-htpasswd', 'thanos-ruler-oauth-htpasswd'),
            volume.fromSecret('secret-thanos-ruler-kube-rbac-proxy', 'thanos-ruler-kube-rbac-proxy'),
          ],
          serviceAccountName: 'thanos-ruler',
          containers: [
            {
              name: 'thanos-ruler-proxy',
              image: $._config.imageRepos.openshiftOauthProxy + ':' + $._config.versions.openshiftOauthProxy,
              ports: [
                {
                  containerPort: 9091,
                  name: 'web',
                },
              ],
              env: [
                {
                  name: "HTTP_PROXY",
                  value: "",
                },
                {
                  name: "HTTPS_PROXY",
                  value: "",
                },
                {
                  name: "NO_PROXY",
                  value: "",
                },
              ],
              args: [
                '-provider=openshift',
                '-https-address=:9091',
                '-http-address=',
                '-email-domain=*',
                '-upstream=http://localhost:10902',
                '-openshift-sar={"resource": "namespaces", "verb": "get"}',
                '-openshift-delegate-urls={"/": {"resource": "namespaces", "verb": "get"}}',
                '-tls-cert=/etc/tls/private/tls.crt',
                '-tls-key=/etc/tls/private/tls.key',
                '-client-secret-file=/var/run/secrets/kubernetes.io/serviceaccount/token',
                '-cookie-secret-file=/etc/proxy/secrets/session_secret',
                '-openshift-service-account=thanos-ruler',
                '-openshift-ca=/etc/pki/tls/cert.pem',
                '-openshift-ca=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
                '-skip-auth-regex=^/metrics',
              ],
              terminationMessagePolicy: 'FallbackToLogsOnError',
              resources: {
                requests: {
                  cpu: '10m',
                  memory: '20Mi',
                },
              },
              volumeMounts: [
                {
                  mountPath: '/etc/tls/private',
                  name: 'secret-thanos-ruler-tls',
                },
                {
                  mountPath: '/etc/proxy/secrets',
                  name: 'secret-thanos-ruler-oauth-cookie',
                },
                {
                  mountPath: '/etc/proxy/htpasswd',
                  name: 'secret-thanos-ruler-oauth-htpasswd',
                },
              ],
            },
          ],
        },
      },

      // statefulSet from kube-thanos is not needed because thanosruler custom resource
      // is used instead.
      statefulSet:: {},

    },
  },
}
