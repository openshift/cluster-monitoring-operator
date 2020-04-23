local k = import 'ksonnet/ksonnet.beta.4/k.libsonnet';
local secret = k.core.v1.secret;
local metrics = import 'telemeter-client/metrics.jsonnet';

{
  _config+:: {
    clusterMonitoringOperatorSelector: 'job="cluster-monitoring-operator"',
    jobs+: {
      ClusterMonitoringOperator: $._config.clusterMonitoringOperatorSelector,
    },
    clusterMonitoringOperator: {
      name: 'cluster-monitoring-operator',
    },
  },

  clusterMonitoringOperator:: {
    service:
      local service = k.core.v1.service;
      local servicePort = k.core.v1.service.mixin.spec.portsType;

      local cmoServicePort = servicePort.newNamed('https', 8443, 'https');

      service.new($._config.clusterMonitoringOperator.name, { app: $._config.clusterMonitoringOperator.name }, [cmoServicePort]) +
      service.mixin.metadata.withLabels({ app: $._config.clusterMonitoringOperator.name }) +
      service.mixin.metadata.withNamespace($._config.namespace) +
      service.mixin.spec.withClusterIp('None') +
      service.mixin.metadata.withAnnotations({
        'service.beta.openshift.io/serving-cert-secret-name': 'cluster-monitoring-operator-tls',
      }),

    serviceMonitor: {
      apiVersion: 'monitoring.coreos.com/v1',
      kind: 'ServiceMonitor',
      metadata: {
        name: $._config.clusterMonitoringOperator.name,
        namespace: $._config.namespace,
        labels: {
          'k8s-app': $._config.clusterMonitoringOperator.name,
        },
      },
      spec: {
        selector: {
          matchLabels: $.clusterMonitoringOperator.service.metadata.labels,
        },
        endpoints: [
          {
            bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            port: 'https',
            scheme: 'https',
            tlsConfig: {
              caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
              serverName: 'server-name-replaced-at-runtime',
            },
          },
        ],
      },
    },

    clusterRole:
      local clusterRole = k.rbac.v1.clusterRole;
      local policyRule = clusterRole.rulesType;

      local namespacesRule = policyRule.new() +
                             policyRule.withApiGroups(['']) +
                             policyRule.withResources(['namespaces']) +
                             policyRule.withVerbs(['get']);

      local rules = [namespacesRule];

      clusterRole.new() +
      clusterRole.mixin.metadata.withName('cluster-monitoring-view') +
      clusterRole.withRules(rules),

    monitoringEditClusterRole:
      local clusterRole = k.rbac.v1.clusterRole;
      local policyRule = clusterRole.rulesType;

      local editRule = policyRule.new() +
                       policyRule.withApiGroups(['monitoring.coreos.com']) +
                       policyRule.withResources(['servicemonitors', 'podmonitors', 'prometheusrules']) +
                       policyRule.withVerbs(['create', 'delete', 'get', 'list', 'update', 'watch']);

      local rules = [editRule];

      clusterRole.new() +
      clusterRole.mixin.metadata.withName('monitoring-edit') +
      clusterRole.withRules(rules),

    monitoringRulesViewClusterRole:
      local clusterRole = k.rbac.v1.clusterRole;
      local policyRule = clusterRole.rulesType;

      local rulesViewRule = policyRule.new() +
                            policyRule.withApiGroups(['monitoring.coreos.com']) +
                            policyRule.withResources(['prometheusrules']) +
                            policyRule.withVerbs(['get', 'list', 'watch']);

      local rules = [rulesViewRule];

      clusterRole.new() +
      clusterRole.mixin.metadata.withName('monitoring-rules-view') +
      clusterRole.withRules(rules),

    monitoringRulesEditClusterRole:
      local clusterRole = k.rbac.v1.clusterRole;
      local policyRule = clusterRole.rulesType;

      local rulesEditRule = policyRule.new() +
                            policyRule.withApiGroups(['monitoring.coreos.com']) +
                            policyRule.withResources(['prometheusrules']) +
                            policyRule.withVerbs(['create', 'delete', 'get', 'list', 'update', 'watch']);

      local rules = [rulesEditRule];

      clusterRole.new() +
      clusterRole.mixin.metadata.withName('monitoring-rules-edit') +
      clusterRole.withRules(rules),
  },
}
