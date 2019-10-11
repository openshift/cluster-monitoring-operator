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

local discoveryRole =
  policyRule.new() +
  policyRule.withApiGroups(['']) +
  policyRule.withResources([
    'services',
    'endpoints',
    'pods',
  ]) +
  policyRule.withVerbs([
    'get',
    'list',
    'watch',
  ]);

local alertmanagerRole =
  policyRule.new() +
  policyRule.withApiGroups(['monitoring.coreos.com']) +
  policyRule.withResources([
    'alertmanagers',
  ]) +
  policyRule.withVerbs(['get']);

{
  prometheusUserWorkload+:: $.prometheus {
    name:: 'user-workload',
    namespace:: $._config.namespaceUserWorkload,
    roleBindingNamespaces:: [$._config.namespaceUserWorkload],

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
        'service.alpha.openshift.io/serving-cert-secret-name': 'prometheus-user-workload-tls',
      }) +
      service.mixin.spec.withType('ClusterIP') +
      service.mixin.spec.withPorts([
        // kube-rbac-proxy
        servicePort.newNamed('metrics', 9091, 'metrics'),
      ]),

    servingCertsCaBundle+:
      configmap.new('serving-certs-ca-bundle', { 'service-ca.crt': '' }) +
      configmap.mixin.metadata.withNamespace($._config.namespaceUserWorkload) +
      configmap.mixin.metadata.withAnnotations({ 'service.alpha.openshift.io/inject-cabundle': 'true' }),

    // As Prometheus is protected by the kube-rbac-proxy it requires the
    // ability to create TokenReview and SubjectAccessReview requests.
    // Additionally in order to authenticate with the Alertmanager it
    // requires `get` method on all `namespaces`, which is the
    // SubjectAccessReview required by the Alertmanager instances.

    clusterRole+:
      clusterRole.withRulesMixin([
        authenticationRole,
        authorizationRole,
        namespacesRole,
        discoveryRole,
        alertmanagerRole,
      ]),

    // This avoids creating service monitors which are already managed by the respective operators.
    rules:: {},
    endpointsEtcd:: {},
    serviceEtcd:: {},
    serviceMonitorEtcd:: {},
    serviceMonitorKubelet:: {},
    serviceMonitorApiserver:: {},
    serviceMonitorKubeScheduler:: {},
    serviceMonitorKubeControllerManager:: {},
    serviceMonitorCoreDNS:: {},
    secretEtcdCerts:: {},

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
                serverName: 'prometheus-user-workload',
              },
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            },
          ],
        },
      },

    prometheus+:
      {
        spec+: {
          arbitraryFSAccessThroughSMs+: {
            deny: true,
          },
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
                  // the user-workload alertmanager configuration points to the openshift-monitoring namespace
                  // since there is no dedicated alertmanager in the user-workload monitoring stack.
                  namespace: $._config.namespace,
                  tlsConfig: {
                    caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                    serverName: 'alertmanager-main.openshift-monitoring.svc',
                  },
                  bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
                },
                super.alertmanagers,
              ),
          },
          resources: {
            requests: {
              memory: '1Gi',
              cpu: '100m',
            },
          },
          securityContext: {},
          secrets: [
            'prometheus-user-workload-tls',
          ],
          configMaps: ['serving-certs-ca-bundle'],
          serviceMonitorSelector: {},
          serviceMonitorNamespaceSelector: {},
          ruleSelector: {},
          ruleNamespaceSelector: {},
          listenLocal: true,
          priorityClassName: 'system-cluster-critical',
          containers: [
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
                  containerPort: 9091,
                  name: 'metrics',
                },
              ],
              args: [
                '--secure-listen-address=0.0.0.0:9091',
                '--upstream=http://127.0.0.1:9090',
                '--tls-cert-file=/etc/tls/private/tls.crt',
                '--tls-private-key-file=/etc/tls/private/tls.key',
                '--tls-cipher-suites=' + std.join(',', $._config.tlsCipherSuites),
              ],
              terminationMessagePolicy: 'FallbackToLogsOnError',
              volumeMounts: [
                {
                  mountPath: '/etc/tls/private',
                  name: 'secret-prometheus-user-workload-tls',
                },
              ],
            },
          ],
        },
      },
  },
}
