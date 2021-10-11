local metrics = import 'github.com/openshift/telemeter/jsonnet/telemeter/metrics.jsonnet';

local cmoRules = import './../rules.libsonnet';
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

  metricsClientCa: {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      name: 'metrics-client-ca',
      namespace: cfg.namespace,
    },
    data: {},
  },

  service: {
    apiVersion: 'v1',
    kind: 'Service',
    metadata: {
      name: cfg.name,
      namespace: cfg.namespace,
      labels: { 'app.kubernetes.io/name': cfg.name },
      annotations: {
        'service.beta.openshift.io/serving-cert-secret-name': 'cluster-monitoring-operator-tls',
      },
    },
    spec: {
      ports: [
        { name: 'https', targetPort: 'https', port: 8443 },
      ],
      selector: { 'app.kubernetes.io/name': cfg.name },
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
            // don't specify the certificate authentication for the operator since
            // it itself creates the client CA copy in the namespace and therefore
            // we cannot use it in the operator's kube-rbac-proxy config
            // TODO: this could be fixed by using library-go's controller setup boilerplate
            //       code
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
        resources: ['apiservers'],
        resourceNames: ['cluster'],
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
        apiGroups: ['certificates.k8s.io'],
        resources: ['certificatesigningrequests'],
        verbs: ['create', 'get', 'list', 'watch', 'update', 'delete'],
      },
      {
        apiGroups: ['certificates.k8s.io'],
        resources: ['certificatesigningrequests/approval', 'certificatesigningrequests/status'],
        verbs: ['get', 'list', 'watch'],
      },
      // The operator needs these permissions to cordon nodes when rebalancing
      // pods.
      {
        apiGroups: [''],
        resources: ['nodes'],
        verbs: ['get', 'list', 'update', 'patch'],
      },
      // The operator needs to get PersistentVolumes to know their storage
      // topology. Based on that information, it will only delete PVCs attached
      // to volumes with a zonal topology when rebalancing pods.
      {
        apiGroups: [''],
        resources: ['persistentvolumes'],
        verbs: ['get'],
      },
    ],
  },

  namespacedClusterRole: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRole',
    metadata: {
      name: 'cluster-monitoring-operator-namespaced',
      annotations: {
        'include.release.openshift.io/ibm-cloud-managed': 'true',
        'include.release.openshift.io/self-managed-high-availability': 'true',
        'include.release.openshift.io/single-node-developer': 'true',
      },
    },
    rules: [
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
        apiGroups: ['policy'],
        resources: ['poddisruptionbudgets'],
        verbs: ['create', 'get', 'update', 'delete'],
      },
      {
        apiGroups: [''],
        resources: ['events'],
        verbs: ['create', 'patch', 'update'],
      },
      // The operator needs to be able to list pods related to a particular
      // workload and delete them so that they can be rescheduled on a
      // different node.
      {
        apiGroups: [''],
        resources: ['pods'],
        verbs: ['list', 'delete'],
      },
      // The operators needs to be able to delete PVCs to rescheduled pods on
      // different nodes because zonal persistent volumes can cause scheduling
      // issues if not deleted beforehand.
      // It also need to watch and update PVC since users are able to mark
      // their PVC for deletion and the operator needs to react upon that.
      {
        apiGroups: [''],
        resources: ['persistentvolumeclaims'],
        verbs: ['get', 'list', 'watch', 'update', 'delete'],
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

  // This role enables access to the Alertmanager APIs and UIs through OAuth proxy.
  monitoringAlertmanagerEditRole: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'Role',
    metadata: {
      name: 'monitoring-alertmanager-edit',
      namespace: cfg.namespace,
    },
    rules: [{
      apiGroups: ['monitoring.coreos.com'],
      resources: ['alertmanagers'],
      verbs: ['patch'],
      resourceNames: ['non-existant'],
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
