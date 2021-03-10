local metrics = import 'telemeter-client/metrics.jsonnet';

local cmoRules = import './rules.libsonnet';
local kubePrometheus = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/mixin/custom.libsonnet';

local defaults = {
  local defaults = self,
  name: 'cluster-monitoring-operator',
  namespace: error 'must provide namespace',
  namespaceUserWorkload: error 'must provide user workload monitoring namespace',
  commonLabels:: {
    'app.kubernetes.io/name': 'cluster-monitoring-operator',
    'app.kubernetes.io/component': 'operator',
    'app.kubernetes.io/part-of': 'openshift-monitoring',
  },
  selectorLabels:: defaults.commonLabels,
};

function(params) {
  local cmo = self,
  local cfg = defaults + params,

  prometheusRule: {
    apiVersion: 'monitoring.coreos.com/v1',
    kind: 'PrometheusRule',
    metadata: {
      labels: cfg.commonLabels + cfg.mixin.ruleLabels,
      name: 'cluster-monitoring-operator-prometheus-rules',
      namespace: cfg.namespace,
    },
    // Since kube-prometheus mixin ships just a few rules the same as CMO, it made sense to bundle them together
    // In the future we might want to move some of rules shipped with CMO to kube-prometheus.
    spec: cmoRules.prometheusRules {
      groups+: kubePrometheus(cfg { name: 'kube-prometheus' }).prometheusRule.spec.groups,
    },
  },

  grpcTlsSecret: {
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: {
      name: 'grpc-tls',
      namespace: cfg.namespace,
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
      name: cfg.name,
      namespace: cfg.namespace,
      labels: { app: cfg.name },
      annotations: {
        'service.beta.openshift.io/serving-cert-secret-name': 'cluster-monitoring-operator-tls',
      },
    },
    spec: {
      ports: [
        { name: 'https', targetPort: 'https', port: 8443 },
      ],
      selector: { app: cfg.name },
      clusterIP: 'None',
    },
  },

  serviceMonitor: {
    apiVersion: 'monitoring.coreos.com/v1',
    kind: 'ServiceMonitor',
    metadata: {
      name: cfg.name,
      namespace: cfg.namespace,
      labels: {
        'app.kubernetes.io/name': cfg.name,
      },
    },
    spec: {
      selector: {
        matchLabels: cmo.service.metadata.labels,
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
      namespace: cfg.namespaceUserWorkload,
    },
    rules: [{
      apiGroups: [''],
      resourceNames: ['user-workload-monitoring-config'],
      resources: ['configmaps'],
      verbs: ['*'],
    }],
  },
}
