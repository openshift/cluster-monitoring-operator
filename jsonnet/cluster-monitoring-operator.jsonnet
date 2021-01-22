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
    grpcTlsSecret: {
      apiVersion: 'v1',
      kind: 'Secret',
      metadata: {
        name: 'grpc-tls',
        namespace: $._config.namespace,
      },
      type: 'Opaque',
      data: {
        'ca.crt': '',
        'ca.key': '',
        'thanos-querier-client.crt': '',
        'thanos-querier-client.key': '',
        'prometheus-server.crt': '',
        'prometheus-server.key': '',
      },
    },

    service: {
      apiVersion: 'v1',
      kind: 'Service',
      metadata: {
        name: $._config.clusterMonitoringOperator.name,
        namespace: $._config.namespace,
        labels: { app: $._config.clusterMonitoringOperator.name },
        annotations: {
          'service.beta.openshift.io/serving-cert-secret-name': 'cluster-monitoring-operator-tls',
        },
      },
      spec: {
        ports: [
          { name: 'https', targetPort: 'https', port: 8443 },
        ],
        selector: { app: $._config.clusterMonitoringOperator.name },
        clusterIP: 'None',
      },
    },

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

    clusterRole: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRole',
      metadata: {
        name: 'cluster-monitoring-view',
      },
      rules: [{
        apiGroups: [''],
        resources: ['namespaces'],
        verbs: ['get'],
      }],
    },

    monitoringEditClusterRole: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRole',
      metadata: {
        name: 'monitoring-edit',
      },
      rules: [{
        apiGroups: ['monitoring.coreos.com'],
        resources: ['servicemonitors', 'podmonitors', 'prometheusrules'],
        verbs: ['*'],
      }],
    },

    monitoringRulesViewClusterRole: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRole',
      metadata: {
        name: 'monitoring-rules-view',
      },
      rules: [{
        apiGroups: ['monitoring.coreos.com'],
        resources: ['prometheusrules'],
        verbs: ['get', 'list', 'watch'],
      }],
    },

    monitoringRulesEditClusterRole: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRole',
      metadata: {
        name: 'monitoring-rules-edit',
      },
      rules: [{
        apiGroups: ['monitoring.coreos.com'],
        resources: ['prometheusrules'],
        verbs: ['*'],
      }],
    },

    userWorkloadConfigEditRole: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'Role',
      metadata: {
        name: 'user-workload-monitoring-config-edit',
        namespace: $._config.namespaceUserWorkload,
      },
      rules: [{
        apiGroups: [''],
        resourceNames: ['user-workload-monitoring-config'],
        resources: ['configmaps'],
        verbs: ['*'],
      }],
    },
  },
}
