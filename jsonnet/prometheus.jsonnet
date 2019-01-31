local k = import 'ksonnet/ksonnet.beta.3/k.libsonnet';
local serviceAccount = k.core.v1.serviceAccount;
local service = k.core.v1.service;
local servicePort = k.core.v1.service.mixin.spec.portsType;
local secret = k.core.v1.secret;
local configmap = k.core.v1.configMap;
local clusterRole = k.rbac.v1.clusterRole;
local policyRule = clusterRole.rulesType;
local selector = k.apps.v1beta2.deployment.mixin.spec.selectorType;

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

{
  prometheus+:: {

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

    // As Prometheus is protected by the oauth proxy it requires the
    // ability to create TokenReview and SubjectAccessReview requests.
    // Additionally in order to authenticate with the Alertmanager it
    // requires `get` method on all `namespaces`, which is the
    // SubjectAccessReview required by the Alertmanager instances.

    clusterRole+:
      clusterRole.withRulesMixin([authenticationRole, authorizationRole, namespacesRole]),

    // OpenShift has the kube-apiserver as well as an aggregated API called
    // OpenShift apiserver, containing all the extended APIs.
    serviceMonitorClusterVersionOperator:
      {
        apiVersion: 'monitoring.coreos.com/v1',
        kind: 'ServiceMonitor',
        metadata: {
          labels: {
            'k8s-app': 'cluster-version-operator',
          },
          name: 'cluster-version-operator',
          namespace: $._config.namespace,
        },
        spec: {
          endpoints: [
            {
              interval: '30s',
              port: 'metrics',
              scheme: 'http',
            },
          ],
          namespaceSelector: {
            matchNames: ['openshift-cluster-version'],
          },
          selector: {
            matchLabels: {
              'k8s-app': 'cluster-version-operator',
            },
          },
        },
      },

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
                    caFile: '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
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

    serviceMonitorOpenShiftApiserver:
      {
        apiVersion: 'monitoring.coreos.com/v1',
        kind: 'ServiceMonitor',
        metadata: {
          name: 'openshift-apiserver',
        },
        spec: {
          endpoints: [
            {
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
              interval: '30s',
              port: 'https',
              scheme: 'https',
              tlsConfig: {
                caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                serverName: 'api.openshift-apiserver.svc',
              },
            },
          ],
          namespaceSelector: {
            matchNames: ['openshift-apiserver'],
          },
          selector: {
          },
        },
      },

    serviceMonitorEtcd+:
      {
        metadata+: {
          namespace: $._config.namespace,
        },
        spec+: {
          namespaceSelector: {
            matchNames: ['kube-system'],
          },
        },
      },

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

    // In OpenShift the kube-scheduler runs in its own namespace, and has a TLS
    // cert from the serving certs controller.

    serviceMonitorKubeScheduler+:
      {
        spec+: {
          jobLabel: null,
          namespaceSelector: {
            matchNames: [
              'openshift-kube-scheduler',
            ],
          },
          selector: {},
          endpoints:
            std.map(
              function(a) a {

                //TODO(brancz): Once OpenShift is based on Kubernetes 1.12 the
                //scheduler will serve metrics on a secure port, then the below
                //commented out code is what we will need without the relabel
                //configs.

                //bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
                interval: '30s',
                port: 'https',
                //scheme: 'https',
                //tlsConfig: {
                //  caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                //  serverName: 'scheduler.openshift-kube-scheduler.svc',
                //},
                relabelings: [{
                  sourceLabels: ['__address__'],
                  action: 'replace',
                  targetLabel: '__address__',
                  regex: '(.+)(?::\\d+)',
                  replacement: '$1:10251',
                }],
              },
              super.endpoints,
            ),
        },
      },

    // In OpenShift the kube-controller-manager runs in its own namespace, and
    // has a TLS cert from the serving certs controller.

    serviceMonitorKubeControllerManager+:
      {
        spec+: {
          jobLabel: null,
          namespaceSelector: {
            matchNames: [
              'openshift-kube-controller-manager',
            ],
          },
          selector: {},
          endpoints:
            std.map(
              function(a) a {

                //TODO(brancz): Once OpenShift is based on Kubernetes 1.12 the
                //controller-manager will serve metrics on a secure port, then
                //the below commented out code is what we will need without the
                //relabel configs.

                //bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
                interval: '30s',
                port: 'https',
                //scheme: 'https',
                //tlsConfig: {
                //  caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                //  serverName: 'controller-manager.openshift-kube-controller-manager.svc',
                //},
                metricRelabelings+: [{
                  action: 'drop',
                  regex: 'rest_client_request_latency_seconds_(bucket|count|sum)',
                  sourceLabels: [
                    '__name__',
                  ],
                }],
                relabelings: [{
                  sourceLabels: ['__address__'],
                  action: 'replace',
                  targetLabel: '__address__',
                  regex: '(.+)(?::\\d+)',
                  replacement: '$1:10252',
                }],
              },
              super.endpoints,
            ),
        },
      },

    // These patches inject the oauth proxy as a sidecar and configures it with
    // TLS. Additionally as the Alertmanager is protected with TLS, authN and
    // authZ it requires some additonal configuration.

    prometheus+:
      {
        spec+: {
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
          securityContext: {},
          resources: {},
          secrets+: [
            'prometheus-k8s-tls',
            'prometheus-k8s-proxy',
            'prometheus-k8s-htpasswd',
            'kube-rbac-proxy',
          ],
          configMaps: ['serving-certs-ca-bundle'],
          serviceMonitorSelector: {},
          serviceMonitorNamespaceSelector: {},
          listenLocal: true,
          containers: [
            {
              name: 'prometheus-proxy',
              image: $._config.imageRepos.openshiftOauthProxy + ':' + $._config.versions.openshiftOauthProxy,
              resources: {},
              ports: [
                {
                  containerPort: 9091,
                  name: 'web',
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
              volumeMounts: [
                {
                  mountPath: '/etc/tls/private',
                  name: 'secret-prometheus-k8s-tls',
                },
                {
                  mountPath: '/etc/kube-rbac-proxy',
                  name: 'secret-' + $.prometheus.kubeRbacProxySecret.metadata.name,
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
            },
          ],
        },
      },
  },
}
