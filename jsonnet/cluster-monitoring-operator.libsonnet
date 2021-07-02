local metrics = import 'github.com/openshift/telemeter/jsonnet/telemeter/metrics.jsonnet';

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
    spec: cmoRules(cfg.mixin) + {
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

  metricsClientCerts: {
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: {
      name: 'metrics-client-certs',
      namespace: cfg.namespace,
    },
    type: 'Opaque',
    data: {},
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

  // This is the base for the cluster-monitoring-operator ClusterRole. It will
  // be extended with the rules from all other ClusterRoles in main.jsonnet.
  clusterRole: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRole',
    metadata: {
      name: 'cluster-monitoring-operator',
      annotations: {
        'include.release.openshift.io/ibm-cloud-managed': 'true',
        'include.release.openshift.io/self-managed-high-availability': 'true',
        'include.release.openshift.io/single-node-developer': 'true',
      },
    },
    rules: [
      {
        apiGroups: ['rbac.authorization.k8s.io'],
        resources: ['roles', 'rolebindings', 'clusterroles', 'clusterrolebindings'],
        verbs: ['create', 'get', 'list', 'watch', 'update', 'delete'],
      },
      {
        apiGroups: ['admissionregistration.k8s.io'],
        resources: ['validatingwebhookconfigurations'],
        verbs: ['create', 'get', 'list', 'watch'],
      },
      {
        apiGroups: ['admissionregistration.k8s.io'],
        resourceNames: ['prometheusrules.openshift.io'],
        resources: ['validatingwebhookconfigurations'],
        verbs: ['create', 'get', 'list', 'watch', 'update', 'delete'],
      },
      {
        apiGroups: [''],
        resources: ['services', 'serviceaccounts', 'configmaps'],
        verbs: ['create', 'get', 'list', 'watch', 'update', 'delete'],
      },
      {
        apiGroups: ['apps'],
        resources: ['deployments', 'daemonsets'],
        verbs: ['create', 'get', 'list', 'watch', 'update', 'delete'],
      },
      {
        apiGroups: ['route.openshift.io'],
        resources: ['routes'],
        verbs: ['create', 'get', 'list', 'watch', 'update', 'delete'],
      },
      {
        apiGroups: ['security.openshift.io'],
        resources: ['securitycontextconstraints'],
        verbs: ['create', 'get', 'list', 'watch', 'update', 'delete'],
      },
      {
        apiGroups: ['apiregistration.k8s.io'],
        resources: ['apiservices'],
        verbs: ['create', 'get', 'list', 'watch', 'update', 'delete'],
      },
      {
        apiGroups: ['config.openshift.io'],
        resources: ['clusterversions'],
        verbs: ['get'],
      },
      {
        apiGroups: ['config.openshift.io'],
        resources: ['infrastructures'],
        verbs: ['get', 'list', 'watch'],
      },
      {
        apiGroups: ['config.openshift.io'],
        resources: ['proxies'],
        verbs: ['get'],
      },
      {
        apiGroups: ['config.openshift.io'],
        resources: ['clusteroperators', 'clusteroperators/status'],
        verbs: ['get', 'update', 'create'],
      },
      {
        apiGroups: ['policy'],
        resources: ['poddisruptionbudgets'],
        verbs: ['create', 'get', 'update', 'delete'],
      },
      {
        apiGroups: ['certificates.k8s.io'],
        resources: ['certificatesigningrequests'],
        verbs: ['create', 'get', 'list', 'watch', 'update', 'delete'],
      },
      {
        apiGroups: ['certificates.k8s.io'],
        resources: ['certificatesigningrequests/approval', 'certificatesigningrequests/status'],
        verbs: ['get', 'list', 'watch'],
      },
    ],
  },

  clusterRoleView: {
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
