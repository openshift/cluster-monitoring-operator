local k = import 'ksonnet/ksonnet.beta.3/k.libsonnet';
local serviceAccount = k.core.v1.serviceAccount;
local service = k.core.v1.service;
local servicePort = k.core.v1.service.mixin.spec.portsType;
local secret = k.core.v1.secret;
local configmap = k.core.v1.configMap;
local clusterRole = k.rbac.v1.clusterRole;
local policyRule = clusterRole.rulesType;
local selector = k.apps.v1beta2.deployment.mixin.spec.selectorType;
local metrics = import 'telemeter-client/metrics.jsonnet';

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

local namespacesRole =
  policyRule.new() +
  policyRule.withApiGroups(['']) +
  policyRule.withResources([
    'namespaces',
  ]) +
  policyRule.withVerbs(['get']);

local alertmanagerRole =
  policyRule.new() +
  policyRule.withApiGroups(['monitoring.coreos.com']) +
  policyRule.withResources([
    'alertmanagers',
  ]) +
  policyRule.withVerbs(['get']);

{
  prometheusK8s+:: {
    trustedCaBundle:
      configmap.new('prometheus-trusted-ca-bundle', { 'ca-bundle.crt': '' }) +
      configmap.mixin.metadata.withNamespace($._config.namespace) +
      configmap.mixin.metadata.withLabels({ 'config.openshift.io/inject-trusted-cabundle': 'true' }),

    grpcTlsSecret:
      secret.new('prometheus-k8s-grpc-tls', {}) +
      secret.mixin.metadata.withNamespace($._config.namespace) +
      secret.mixin.metadata.withLabels({ 'k8s-app': 'prometheus-k8s' }),

    // OpenShift route to access the Prometheus UI.

    route: {
      apiVersion: 'v1',
      kind: 'Route',
      metadata: {
        name: 'prometheus-k8s',
        namespace: $._config.namespace,
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

    serviceAccount+:
      serviceAccount.mixin.metadata.withAnnotations({
        'serviceaccounts.openshift.io/oauth-redirectreference.prometheus-k8s': '{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"prometheus-k8s"}}',
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
    // the serving port is 9091 instead of the 9090 default.

    service+:
      service.mixin.metadata.withAnnotations({
        'service.alpha.openshift.io/serving-cert-secret-name': 'prometheus-k8s-tls',
      }) +
      service.mixin.spec.withType('ClusterIP') +
      service.mixin.spec.withPorts([
        servicePort.newNamed('web', 9091, 'web'),
        servicePort.newNamed('tenancy', 9092, 'tenancy'),
      ]),

    servingCertsCaBundle+:
      configmap.new('serving-certs-ca-bundle', { 'service-ca.crt': '' }) +
      configmap.mixin.metadata.withNamespace($._config.namespace) +
      configmap.mixin.metadata.withAnnotations({ 'service.alpha.openshift.io/inject-cabundle': 'true' }),

    // Even though this bundle will be frequently rotated by the CSR
    // controller, there is no need to add a ConfigMap reloader to
    // the Prometheus Pods because Prometheus automatically reloads
    // its cert pool every 5 seconds.
    kubeletServingCaBundle+:
      configmap.new('kubelet-serving-ca-bundle', { 'ca-bundle.crt': '' }) +
      configmap.mixin.metadata.withNamespace($._config.namespace),

    // As Prometheus is protected by the oauth proxy it requires the
    // ability to create TokenReview and SubjectAccessReview requests.
    // Additionally in order to authenticate with the Alertmanager it
    // requires `get` method on all `namespaces`, which is the
    // SubjectAccessReview required by the Alertmanager instances.

    clusterRole+:
      clusterRole.withRulesMixin([authenticationRole, authorizationRole, namespacesRole, alertmanagerRole]),

    // The proxy secret is there to encrypt session created by the oauth proxy.

    proxySecret:
      secret.new('prometheus-k8s-proxy', {}) +
      secret.mixin.metadata.withNamespace($._config.namespace) +
      secret.mixin.metadata.withLabels({ 'k8s-app': 'prometheus-k8s' }),

    htpasswdSecret:
      secret.new('prometheus-k8s-htpasswd', {}) +
      secret.mixin.metadata.withNamespace($._config.namespace) +
      secret.mixin.metadata.withLabels({ 'k8s-app': 'prometheus-k8s' }),

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

      secret.new('kube-rbac-proxy', config) +
      secret.mixin.metadata.withNamespace($._config.namespace) +
      secret.mixin.metadata.withLabels({ 'k8s-app': 'prometheus-k8s' }),

    // This changes the kubelet's certificates to be validated when
    // scraping.

    serviceMonitorKubelet+:
      {
        spec+: {
          endpoints:
            std.map(
              function(e)
                e {
                  tlsConfig+: {
                    caFile: '/etc/prometheus/configmaps/kubelet-serving-ca-bundle/ca-bundle.crt',
                    insecureSkipVerify: false,
                  },
                },
              super.endpoints,
            ) +
            [{
              interval: '30s',
              port: 'https-metrics',
              relabelings: [
                {
                  sourceLabels: ['__address__'],
                  action: 'replace',
                  targetLabel: '__address__',
                  regex: '(.+)(?::\\d+)',
                  replacement: '$1:9537',
                },
                {
                  sourceLabels: ['endpoint'],
                  action: 'replace',
                  targetLabel: 'endpoint',
                  replacement: 'crio',
                },
                {
                  action: 'replace',
                  targetLabel: 'job',
                  replacement: 'crio',
                },
              ],
            }],
        },
      },

    serviceMonitorEtcd+:
      {
        metadata+: {
          namespace: $._config.namespace,
        },
        spec+: {
          namespaceSelector: {
            matchNames: ['openshift-etcd'],
          },
        },
      },

    // This avoids creating service monitors which are already managed by the respective operators.

    serviceMonitorApiserver:: {},
    serviceMonitorKubeScheduler:: {},
    serviceMonitorKubeControllerManager:: {},
    serviceMonitorCoreDNS:: {},

    // This changes the Prometheuses to be scraped with TLS, authN and
    // authZ, which are not present in kube-prometheus.

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
                serverName: 'prometheus-k8s',
              },
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            },
          ],
        },
      },

    // These patches inject the oauth proxy as a sidecar and configures it with
    // TLS. Additionally as the Alertmanager is protected with TLS, authN and
    // authZ it requires some additonal configuration.

    prometheus+:
      {
        spec+: {
          thanos+: {
            baseImage: $._config.imageRepos.openshiftThanos,
            version: $._config.versions.openshiftThanos,
            // disable thanos object storage
            objectStorageConfig:: null,
          },
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
                },
                super.alertmanagers,
              ),
          },
          resources: {
            requests: {
              memory: '1Gi',
              cpu: '200m',
            },
          },
          securityContext: {},
          secrets+: [
            'prometheus-k8s-tls',
            'prometheus-k8s-proxy',
            'prometheus-k8s-htpasswd',
            'kube-rbac-proxy',
          ],
          configMaps: ['serving-certs-ca-bundle', 'kubelet-serving-ca-bundle'],
          serviceMonitorSelector: {},
          serviceMonitorNamespaceSelector: {},
          ruleSelector: {},
          ruleNamespaceSelector: {},
          listenLocal: true,
          priorityClassName: 'system-cluster-critical',
          containers: [
            {
              name: 'prometheus-proxy',
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
                '-openshift-service-account=prometheus-k8s',
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
                  name: 'secret-prometheus-k8s-tls',
                },
                {
                  mountPath: '/etc/proxy/secrets',
                  name: 'secret-prometheus-k8s-proxy',
                },
                {
                  mountPath: '/etc/proxy/htpasswd',
                  name: 'secret-prometheus-k8s-htpasswd',
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
                  name: 'secret-' + $.prometheusK8s.kubeRbacProxySecret.metadata.name,
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
            },
            {
              name: 'prometheus',
            },
          ],
        },
      },
  },
}
