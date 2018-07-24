local k = import 'ksonnet/ksonnet.beta.3/k.libsonnet';

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

      local cmoServicePort = servicePort.newNamed('http', 8080, 'http');

      service.new($._config.clusterMonitoringOperator.name, { app: $._config.clusterMonitoringOperator.name }, [cmoServicePort]) +
      service.mixin.metadata.withLabels({ app: $._config.clusterMonitoringOperator.name }) +
      service.mixin.metadata.withNamespace($._config.namespace) +
      service.mixin.spec.withClusterIp('None'),

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
            port: 'http',
          },
        ],
      },
    },
  },
}
