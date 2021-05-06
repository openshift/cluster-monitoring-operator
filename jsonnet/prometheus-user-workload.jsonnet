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

// By default authenticated service accounts are assigned to the `restricted` SCC which implies MustRunAsRange.
// This is problematic with statefulsets as UIDs (and file permissions) can change if SCCs are elevated.
// Instead, this sets the `nonroot` SCC in conjunction with a static fsGroup and runAsUser security context below
// to be immune against UID changes.
local sccRole =
  policyRule.new() +
  policyRule.withApiGroups(['security.openshift.io']) +
  policyRule.withResources([
    'securitycontextconstraints',
  ]) +
  policyRule.withResourceNames([
    'nonroot',
  ]) +
  policyRule.withVerbs(['use']);


{
  prometheusUserWorkload+:: $.prometheus {
    name:: 'user-workload',
    namespace:: $._config.namespaceUserWorkload,
    roleBindingNamespaces:: [$._config.namespaceUserWorkload],

    grpcTlsSecret:
      secret.new('prometheus-user-workload-grpc-tls', {}) +
      secret.mixin.metadata.withNamespace($._config.namespaceUserWorkload) +
      secret.mixin.metadata.withLabels({ 'k8s-app': 'prometheus-k8s' }),

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
        'service.beta.openshift.io/serving-cert-secret-name': 'prometheus-user-workload-tls',
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
        sccRole,
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
              port: 'metrics',
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
          overrideHonorTimestamps: true,
          overrideHonorLabels: true,
          ignoreNamespaceSelectors: true,
          enforcedNamespaceLabel: 'namespace',
          ruleSelector: {
            matchLabels: {
              'openshift.io/prometheus-rule-evaluation-scope': 'leaf-prometheus',
            },
          },
          arbitraryFSAccessThroughSMs+: {
            deny: true,
          },
          affinity+: {
            podAntiAffinity: {
              // Apply HA conventions
              requiredDuringSchedulingIgnoredDuringExecution: [
                {
                  namespaces: [$._config.namespaceUserWorkload],
                  labelSelector: {
                    matchExpressions: [{
                      key: 'prometheus',
                      operator: 'In',
                      values: ['user-workload'],
                    }]
                  },
                  topologyKey: 'kubernetes.io/hostname',
                },
              ],
            },
          },
          thanos+: {
            image: $._config.imageRepos.openshiftThanos + ':' + $._config.versions.openshiftThanos,
            version: $._config.versions.openshiftThanos,
            // disable thanos object storage
            objectStorageConfig:: null,
            resources: {
              requests: {
                cpu: '1m',
                memory: '100Mi',
              },
            },
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
                  apiVersion: 'v2',
                },
                super.alertmanagers,
              ),
          },
          resources: {
            requests: {
              memory: '30Mi',
              cpu: '6m',
            },
          },
          securityContext: {
            fsGroup: 65534,
            runAsNonRoot: true,
            runAsUser: 65534,
          },
          secrets: [
            'prometheus-user-workload-tls',
          ],
          configMaps: ['serving-certs-ca-bundle'],
          serviceMonitorSelector: {},
          serviceMonitorNamespaceSelector: {},
          ruleNamespaceSelector: {},
          listenLocal: true,
          priorityClassName: 'openshift-user-critical',
          containers: [
            {
              name: 'kube-rbac-proxy',
              image: $._config.imageRepos.kubeRbacProxy + ':' + $._config.versions.kubeRbacProxy,
              resources: {
                requests: {
                  memory: '10Mi',
                  cpu: '1m',
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
              resources: {
                requests: {
                  memory: '17Mi',
                  cpu: '1m',
                },
              },
              volumeMounts: [
                {
                  mountPath: '/etc/tls/grpc',
                  name: 'secret-grpc-tls',
                },
              ],
            },
            {
              name: 'config-reloader',
              resources: {
                requests: {
                  cpu: '1m',
                  memory: '10Mi',
                },
              },
            },
          ],
        },
      },
  },
}
