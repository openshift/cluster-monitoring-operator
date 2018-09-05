local k = import 'ksonnet/ksonnet.beta.3/k.libsonnet';
local serviceAccount = k.core.v1.serviceAccount;
local service = k.core.v1.service;
local servicePort = k.core.v1.service.mixin.spec.portsType;
local secret = k.core.v1.secret;
local clusterRole = k.rbac.v1.clusterRole;
local policyRule = clusterRole.rulesType;
local selector = k.apps.v1beta2.deployment.mixin.spec.selectorType;

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

local namespacesRole = policyRule.new() +
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
      service.mixin.spec.withPorts(servicePort.newNamed('web', 9091, 'web')),

    // As Prometheus is protected by the oauth proxy it requires the
    // ability to create TokenReview and SubjectAccessReview requests.
    // Additionally in order to authenticate with the Alertmanager it
    // requires `get` method on all `namespaces`, which is the
    // SubjectAccessReview required by the Alertmanager instances.

    clusterRole+:
      clusterRole.withRulesMixin([authenticationRole, authorizationRole, namespacesRole]),

    // OpenShift currently has the kube-controller-manager and
    // kube-scheduler combined in one component called the
    // kube-controllers. This Service and ServiceMonitor enable scraping
    // its metrics.

    kubeControllersService:
      local service = k.core.v1.service;
      local servicePort = k.core.v1.service.mixin.spec.portsType;

      local kubeControllersPort = servicePort.newNamed('http-metrics', 8444, 8444);

      service.new('kube-controllers', {
        'openshift.io/component': 'controllers',
        'openshift.io/control-plane': 'true',
      }, kubeControllersPort) +
      service.mixin.metadata.withNamespace('kube-system') +
      service.mixin.metadata.withLabels({ 'k8s-app': 'kube-controllers' }) +
      service.mixin.spec.withClusterIp('None'),

    serviceMonitorKubeControllers:
      {
        apiVersion: 'monitoring.coreos.com/v1',
        kind: 'ServiceMonitor',
        metadata: {
          labels: {
            'k8s-app': 'kube-controllers',
          },
          name: 'kube-controllers',
        },
        spec: {
          endpoints: [
            {
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
              interval: '30s',
              port: 'http-metrics',
              scheme: 'https',
              tlsConfig: {
                caFile: '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
              },
            },
          ],
          jobLabel: 'k8s-app',
          namespaceSelector: {
            matchNames: ['kube-system'],
          },
          selector: {
            matchLabels: {
              'k8s-app': 'kube-controllers',
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

    // This changes the kubelet's certificates to be validated when
    // scraping.

    serviceMonitorKubelet:
      {
        apiVersion: 'monitoring.coreos.com/v1',
        kind: 'ServiceMonitor',
        metadata: {
          labels: {
            'k8s-app': 'kubelet',
          },
          name: 'kubelet',
        },
        spec: {
          endpoints: [
            {
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
              interval: '30s',
              port: 'https-metrics',
              scheme: 'https',
              tlsConfig: {
                caFile: '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
              },
            },
            {
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
              honorLabels: true,
              interval: '30s',
              path: '/metrics/cadvisor',
              port: 'https-metrics',
              scheme: 'https',
              tlsConfig: {
                caFile: '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
              },
            },
          ],
          jobLabel: 'k8s-app',
          namespaceSelector: {
            matchNames: ['kube-system'],
          },
          selector: {
            matchLabels: {
              'k8s-app': 'kubelet',
            },
          },
        },
      },

    serviceMonitorMeteringReportingOperator:
      {
        kind: 'ServiceMonitor',
        apiVersion: 'monitoring.coreos.com/v1',
        metadata: {
          name: 'metering-reporting-operator',
          namespace: $._config.namespace,
          labels: {
            'k8s-app': 'reporting-operator',
          },
        },
        spec: {
          jobLabel: 'k8s-app',
          endpoints: [
            {
              tlsConfig: {
                serverName: 'reporting-operator-metrics.openshift-metering.svc',
                caFile: '/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt',
              },
              scheme: 'https',
              port: 'metrics',
              interval: '30s',
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            },
          ],
          namespaceSelector: {
            matchNames: [
              'openshift-metering',
            ],
          },
          selector: {
            matchLabels: {
              metrics: 'true',
              app: 'reporting-operator',
            },
          },
        },
      },

    serviceMonitorMeteringPresto:
      {
        kind: 'ServiceMonitor',
        apiVersion: 'monitoring.coreos.com/v1',
        metadata: {
          name: 'metering-presto',
          namespace: $._config.namespace,
          labels: {
            'k8s-app': 'metering-presto',
          },
        },
        spec: {
          jobLabel: 'k8s-app',
          endpoints: [
            {
              scheme: 'http',
              port: 'metrics',
              interval: '30s',
            },
          ],
          namespaceSelector: {
            matchNames: [
              'openshift-metering',
            ],
          },
          selector: {
            matchLabels: {
              metrics: 'true',
              app: 'presto',
            },
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
                caFile: '/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt',
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
          alerting+: {
            alertmanagers:
              std.map(
                function(a) a {
                  scheme: 'https',
                  tlsConfig: {
                    caFile: '/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt',
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
          ],
          serviceMonitorSelector: selector.withMatchExpressions({ key: 'k8s-app', operator: 'Exists' }),
          serviceMonitorNamespaceSelector: selector.withMatchExpressions({ key: 'openshift.io/cluster-monitoring', operator: 'Exists' }),
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
          ],
        },
      },
  },
}
