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

local thanosRulerRules =
  (import 'github.com/thanos-io/thanos/mixin/thanos/alerts/rule.libsonnet') {
    rule+:: {
      selector: 'job="thanos-ruler"',
    },
  };

{
  local thanosRulerName = 'user-workload',
  local thanosRulerConfig = super._config + {
    name: thanosRulerName,
    namespace: 'openshift-user-workload-monitoring',
    labels: {
      'app.kubernetes.io/name': thanosRulerName,
    },
    selectorLabels: {
      app: 'thanos-ruler',
      'thanos-ruler': thanosRulerName,
    },
    ports: {
      web: 9091,
      grpc: 10901,
    },
  },

  thanos+:: {
    image:: thanosRulerConfig.imageRepos.openshiftThanos + ':' + thanosRulerConfig.versions.openshiftThanos,

    ruler+: {

      thanosRulerPrometheusRule: {
        apiVersion: 'monitoring.coreos.com/v1',
        kind: 'PrometheusRule',
        metadata: {
          name: 'thanos-ruler',
          namespace: 'openshift-user-workload-monitoring',
        },
        spec: thanosRulerRules.prometheusAlerts,
      },

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

      clusterRoleBindingMonitoring:
        local clusterRoleBinding = k.rbac.v1.clusterRoleBinding;

        clusterRoleBinding.new() +
        clusterRoleBinding.mixin.metadata.withName('thanos-ruler-monitoring') +
        clusterRoleBinding.mixin.roleRef.withApiGroup('rbac.authorization.k8s.io') +
        clusterRoleBinding.mixin.roleRef.withName('cluster-monitoring-view') +
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

      // alertmanager config holds the http configuration
      // for communication between thanos ruler and alertmanager.
      alertmanagersConfigSecret:
        local alertmanagerConfig = {
          'alertmanagers.yaml': std.manifestYamlDoc({
            alertmanagers: [{
              http_config: {
                bearer_token_file: '/var/run/secrets/kubernetes.io/serviceaccount/token',
                tls_config: {
                  ca_file: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                  server_name: 'alertmanager-main.openshift-monitoring.svc',
                },
              },
              static_configs: ['dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc'],
              scheme: 'https',
              api_version: 'v2',
            }],
          }),
        };

        secret.new('thanos-ruler-alertmanagers-config', {}) +
        secret.mixin.metadata.withNamespace(thanosRulerConfig.namespace) +
        secret.mixin.metadata.withLabels({ 'k8s-app': 'thanos-ruler' }) +
        secret.withStringData(alertmanagerConfig),

      // query config which holds http configuration
      // for communication between thanos ruler and thanos querier.
      queryConfigSecret:
        local queryConfig = {
          'query.yaml': std.manifestYamlDoc([{
            http_config: {
              bearer_token_file: '/var/run/secrets/kubernetes.io/serviceaccount/token',
              tls_config: {
                ca_file: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                server_name: 'thanos-querier.openshift-monitoring.svc',
              },
            },
            static_configs: ['thanos-querier.openshift-monitoring.svc:9091'],
            scheme: 'https',
          }]),
        };

        secret.new('thanos-ruler-query-config', {}) +
        secret.mixin.metadata.withNamespace(thanosRulerConfig.namespace) +
        secret.mixin.metadata.withLabels({ 'k8s-app': 'thanos-ruler' }) +
        secret.withStringData(queryConfig),

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
          'thanos-ruler',
          thanosRulerConfig.selectorLabels,
          [
            ports.newNamed('web', thanosRulerConfig.ports.web, 'web'),
            ports.newNamed('grpc', thanosRulerConfig.ports.grpc, 'grpc'),
          ],
        ) +
        // The following annotation will instruct the serving certs controller
        // to synthesize the "thanos-ruler-tls" secret.
        // Hence, we don't need to declare that secret explicitly.
        service.mixin.metadata.withAnnotations({
          'service.beta.openshift.io/serving-cert-secret-name': 'thanos-ruler-tls',
        }) +
        service.mixin.metadata.withLabels(thanosRulerConfig.labels) +
        service.mixin.metadata.withNamespace(thanosRulerConfig.namespace) +
        // The ClusterIP is explicitly set, as it signifies the
        // cluster-monitoring-operator, that when reconciling this service the
        // cluster IP needs to be retained.
        service.mixin.spec.withType('ClusterIP') +
        service.mixin.spec.withSessionAffinity('ClientIP'),

      serviceMonitor: {
        apiVersion: 'monitoring.coreos.com/v1',
        kind: 'ServiceMonitor',
        metadata: {
          name: 'thanos-ruler',
          namespace: thanosRulerConfig.namespace,
          labels: {
            'k8s-app': 'thanos-ruler',
          },
        },
        spec: {
          selector: {
            matchLabels: thanosRulerConfig.labels,
          },
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
          grpcServerTlsConfig: {
            certFile: '/etc/tls/grpc/server.crt',
            keyFile: '/etc/tls/grpc/server.key',
            caFile: '/etc/tls/grpc/ca.crt',
          },
          alertmanagersConfig: {
            key: 'alertmanagers.yaml',
            name: 'thanos-ruler-alertmanagers-config',
          },
          queryConfig: {
            key: 'query.yaml',
            name: 'thanos-ruler-query-config',
          },
          enforcedNamespaceLabel: 'namespace',
          listenLocal: true,
          ruleSelector: {},
          ruleNamespaceSelector: {},
          volumes: [
            {
              configmap: {
                name: 'serving-certs-ca-bundle',
              },
              name: 'serving-certs-ca-bundle',
            },
            volume.fromSecret('secret-thanos-ruler-tls', 'thanos-ruler-tls'),
            volume.fromSecret('secret-thanos-ruler-oauth-cookie', 'thanos-ruler-oauth-cookie'),
            volume.fromSecret('secret-thanos-ruler-oauth-htpasswd', 'thanos-ruler-oauth-htpasswd'),
          ],
          serviceAccountName: 'thanos-ruler',
          containers: [
            {
              name: 'thanos-ruler',
              resources: {
                requests: {
                  memory: '21Mi',
                  cpu: '1m',
                },
              },
              terminationMessagePolicy: 'FallbackToLogsOnError',
              volumeMounts: [
                {
                  mountPath: '/etc/tls/private',
                  name: 'secret-thanos-ruler-tls',
                },
                {
                  mountPath: '/etc/tls/grpc',
                  name: 'secret-grpc-tls',
                },
                {
                  mountPath: '/etc/prometheus/configmaps/serving-certs-ca-bundle',
                  name: 'serving-certs-ca-bundle',
                },
              ],
            },
            {
              name: 'thanos-ruler-proxy',
              image: $._config.imageRepos.openshiftOauthProxy + ':' + $._config.versions.openshiftOauthProxy,
              ports: [
                {
                  containerPort: thanosRulerConfig.ports.web,
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
                  cpu: '1m',
                  memory: '12Mi',
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
              ],
            },
            {
              name: 'rules-configmap-reloader',
              resources: {
                requests: {
                  memory: '5Mi',
                  cpu: '1m',
                },
              },
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
