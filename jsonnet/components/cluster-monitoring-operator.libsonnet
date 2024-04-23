local metrics = import 'github.com/openshift/telemeter/jsonnet/telemeter/metrics.jsonnet';

local cmoRules = import './../rules.libsonnet';
local kubePrometheus = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/mixin/custom.libsonnet';
local metricsAdapter = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/prometheus-adapter.libsonnet';

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

  local clusterRoleAggregatedMetricsReader = metricsAdapter(cfg).clusterRoleAggregatedMetricsReader,

  '0alertingrulesCustomResourceDefinition': import './../crds/alertingrules-custom-resource-definition.json',
  '0alertrelabelconfigsCustomResourceDefinition': import './../crds/alertrelabelconfigs-custom-resource-definition.json',

  clusterRoleAggregatedMetricsReader: clusterRoleAggregatedMetricsReader {
    metadata+: {
      labels+: {
        'app.kubernetes.io/name': cfg.name,
        'app.kubernetes.io/component': 'metrics-adapter',
        'rbac.authorization.k8s.io/aggregate-to-cluster-reader': 'true',
      },
    },
  },

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

  metricsServerClientCerts: {
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: {
      name: 'metrics-server-client-certs',
      namespace: cfg.namespace,
    },
    type: 'Opaque',
    data: {},
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

  federateClientCerts: {
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: {
      name: 'federate-client-certs',
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
        matchLabels: { 'app.kubernetes.io/name': cfg.name },
      },
      endpoints: [
        {
          port: 'https',
          scheme: 'https',
          tlsConfig: {
            certFile: '/etc/prometheus/secrets/metrics-client-certs/tls.crt',
            keyFile: '/etc/prometheus/secrets/metrics-client-certs/tls.key',
            insecureSkipVerify: false,
            caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
            serverName: std.format('%s.%s.svc', [cfg.name, cfg.namespace]),
          },
          metricRelabelings: [
            // Drop metrics that come automatically from the Kubernetes
            // apiserver package but aren't interesting for the cluster
            // monitoring operator.
            {
              sourceLabels: ['__name__'],
              action: 'drop',
              regex: '(apiserver|go_sched|workqueue)_.+',
            },
          ],
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
      name: cfg.name,
      annotations: {
        'include.release.openshift.io/ibm-cloud-managed': 'true',
        'include.release.openshift.io/hypershift': 'true',
        'include.release.openshift.io/self-managed-high-availability': 'true',
        'include.release.openshift.io/single-node-developer': 'true',
      },
    },
    rules: [
      // The permissions mixed-in in main.jsonnet don't seem to include GET
      // access on these, but the operator needs them when fetching
      // OwnerReferences.
      //
      // See: https://bugzilla.redhat.com/show_bug.cgi?id=2057403
      {
        apiGroups: ['apps'],
        resources: ['replicasets'],
        verbs: ['get'],
      },
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
        resourceNames: ['prometheusrules.openshift.io', 'alertmanagerconfigs.openshift.io'],
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
        verbs: ['get', 'list', 'watch'],
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
        verbs: ['get', 'update', 'create', 'list', 'watch'],
      },
      {
        apiGroups: ['config.openshift.io'],
        resources: ['consoles'],
        verbs: ['get', 'list', 'watch'],
      },
      // The operator needs to know whether TechPreview features are enabled or not.
      {
        apiGroups: ['config.openshift.io'],
        resources: ['featuregates'],
        verbs: ['get', 'list', 'watch'],
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
      // The operator needs the list permissions on nodes to estimate the cluster's pod capacity.
      {
        apiGroups: [''],
        resources: ['nodes'],
        verbs: ['list'],
      },
      // The operator needs to patch operator console to add monitoring console-plugin
      {
        apiGroups: ['operator.openshift.io'],
        resources: ['consoles'],
        verbs: ['get', 'patch'],
      },
      // CMO needs permissions to create and update console plugin
      {
        apiGroups: ['console.openshift.io'],
        resources: ['consoleplugins'],
        verbs: ['get', 'create', 'update'],
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
        'include.release.openshift.io/hypershift': 'true',
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
      {
        apiGroups: ['monitoring.coreos.com'],
        resourceNames: ['user-workload', 'main'],
        resources: ['alertmanagers/api'],
        verbs: ['*'],
      },
    ],
  },

  // Defines permisssions required for alert customization feature. CMO needs:
  // - get/list/watch permissions on alertingrules and alertrelabelconfigs to detect changes requiring reconciliation.
  // - all permissions on alertingrules/finalizers to set the `ownerReferences` field on generated prometheusrules.
  // - all permissions on alertingrules/status to set the status of alertingrules.
  alertCustomizationRole: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'Role',
    metadata: {
      name: 'cluster-monitoring-operator-alert-customization',
      namespace: cfg.namespace,
      annotations: {
        'include.release.openshift.io/ibm-cloud-managed': 'true',
        'include.release.openshift.io/hypershift': 'true',
        'include.release.openshift.io/self-managed-high-availability': 'true',
        'include.release.openshift.io/single-node-developer': 'true',
      },
    },
    rules: [
      {
        apiGroups: ['monitoring.openshift.io'],
        resources: ['alertingrules', 'alertrelabelconfigs'],
        verbs: ['get', 'list', 'watch'],
      },
      {
        apiGroups: ['monitoring.openshift.io'],
        resources: ['alertingrules/finalizers', 'alertingrules/status'],
        verbs: ['*'],
      },
    ],
  },

  // This cluster role enables access to the Observe page in the admin console
  // and the different API services.
  // In previous version, anyone with a "get" access on "namespace" resource
  // can access the web endpoint. But KubeRBACProxy takes "get" verb as HTTP GET
  // method, while the console access the web endpoint using HTTP POST method.
  // A dedicated resource will be used to implementing this security setting.
  clusterRoleView: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRole',
    metadata: {
      name: 'cluster-monitoring-view',
    },
    rules: [
      {
        apiGroups: [''],
        resources: ['namespaces'],
        verbs: ['get'],
      },
      {
        apiGroups: ['monitoring.coreos.com'],
        resources: ['prometheuses/api'],
        resourceNames: ['k8s'],
        verbs: ['get', 'create', 'update'],
      },
    ],
  },

  clusterMonitoringApiRole: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'Role',
    metadata: {
      name: 'cluster-monitoring-metrics-api',
      namespace: cfg.namespace,
    },
    rules: [
      {
        apiGroups: ['monitoring.coreos.com'],
        resources: ['prometheuses/api'],
        resourceNames: ['k8s'],
        verbs: ['get', 'create', 'update'],
      },
    ],
  },

  // This role enables read/write access to the platform Alertmanager API
  // through kube-rbac-proxy.
  monitoringAlertmanagerEditRole: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'Role',
    metadata: {
      name: 'monitoring-alertmanager-edit',
      namespace: cfg.namespace,
    },
    rules: [
      {
        // this permission used to be required when Alertmanager was protected via OAuth proxy.
        // TODO: remove it after OCP 4.16 is released.
        apiGroups: ['monitoring.coreos.com'],
        resources: ['alertmanagers'],
        verbs: ['patch'],
        resourceNames: ['non-existant'],
      },
      {
        apiGroups: ['monitoring.coreos.com'],
        resources: ['alertmanagers/api'],
        resourceNames: ['main'],
        verbs: ['*'],
      },
    ],
  },

  // This role enables read access to the platform Alertmanager API
  // through kube-rbac-proxy.
  monitoringAlertmanagerViewRole: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'Role',
    metadata: {
      name: 'monitoring-alertmanager-view',
      namespace: cfg.namespace,
    },
    rules: [
      {
        apiGroups: ['monitoring.coreos.com'],
        resources: ['alertmanagers/api'],
        resourceNames: ['main'],
        verbs: ['get', 'list'],
      },
    ],
  },

  // This role provides read access to the user-workload Alertmanager API.
  // We use a fake subresource 'api' to map to the /api/* endpoints of the
  // Alertmanager API.
  // Using "nonResourceURLs" doesn't work because authenticated users and
  // service accounts are allowed to get /api/* by default.
  // See https://issues.redhat.com/browse/OCPBUGS-17850.
  userWorkloadAlertmanagerApiReader: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'Role',
    metadata: {
      name: 'monitoring-alertmanager-api-reader',
      namespace: cfg.namespaceUserWorkload,
    },
    rules: [{
      apiGroups: ['monitoring.coreos.com'],
      resources: ['alertmanagers/api'],
      resourceNames: ['user-workload'],
      verbs: ['get', 'list'],
    }],
  },

  // This role provides read/write access to the user-workload Alertmanager API.
  // See the 'monitoring-alertmanager-api-reader' role for details.
  userWorkloadAlertmanagerApiWriter: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'Role',
    metadata: {
      name: 'monitoring-alertmanager-api-writer',
      namespace: cfg.namespaceUserWorkload,
    },
    rules: [{
      apiGroups: ['monitoring.coreos.com'],
      resources: ['alertmanagers/api'],
      resourceNames: ['user-workload'],
      verbs: ['*'],
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

  // This cluster role can be referenced in a RoleBinding object to provide read access to PrometheusRule objects for a project.
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

  // This cluster role can be referenced in a RoleBinding object to provide read/write access to PrometheusRule objects for a project.
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

  // This role provides read/write access to the user-workload monitoring configuration.
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
      verbs: ['get', 'list', 'watch', 'patch', 'update'],
    }],
  },

  // This cluster role can be referenced in a RoleBinding object to provide read/write access to AlertmanagerConfiguration objects for a project.
  alertingEditClusterRole: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRole',
    metadata: {
      name: 'alert-routing-edit',
    },
    rules: [{
      apiGroups: ['monitoring.coreos.com'],
      resources: ['alertmanagerconfigs'],
      verbs: ['*'],
    }],
  },
}
