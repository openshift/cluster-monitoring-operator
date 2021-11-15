local removeLimits = (import './utils/remove-limits.libsonnet').removeLimits;
local addAnnotations = (import './utils/add-annotations.libsonnet').addAnnotations;
local sanitizeAlertRules = (import './utils/sanitize-rules.libsonnet').sanitizeAlertRules;

local alertmanager = import './components/alertmanager.libsonnet';
local grafana = import './components/grafana.libsonnet';
local kubeStateMetrics = import './components/kube-state-metrics.libsonnet';
local controlPlane = import './components/control-plane.libsonnet';
local nodeExporter = import './components/node-exporter.libsonnet';
local prometheusAdapter = import './components/prometheus-adapter.libsonnet';
local prometheusOperator = import './components/prometheus-operator.libsonnet';
local prometheusOperatorUserWorkload = import './components/prometheus-operator-user-workload.libsonnet';
local prometheus = import './components/prometheus.libsonnet';
local prometheusUserWorkload = import './components/prometheus-user-workload.libsonnet';
local clusterMonitoringOperator = import './components/cluster-monitoring-operator.libsonnet';

local thanosRuler = import './components/thanos-ruler.libsonnet';
local thanosQuerier = import './components/thanos-querier.libsonnet';

local openshiftStateMetrics = import './components/openshift-state-metrics.libsonnet';
local telemeterClient = import './components/telemeter-client.libsonnet';

// Common configuration
local commonConfig = {
  namespace: 'openshift-monitoring',
  namespaceUserWorkload: 'openshift-user-workload-monitoring',
  clusterMonitoringNamespaceSelector: {
    matchLabels: {
      'openshift.io/cluster-monitoring': 'true',
    },
  },
  userWorkloadMonitoringNamespaceSelector: {
    matchExpressions: [
      {
        key: 'openshift.io/cluster-monitoring',
        operator: 'NotIn',
        values: ['true'],
      },
      {
        key: 'openshift.io/user-monitoring',
        operator: 'NotIn',
        values: ['false'],
      },
    ],
  },
  mixinNamespaceSelector: 'namespace=~"(openshift-.*|kube-.*|default)"',
  prometheusName: 'k8s',
  ruleLabels: {
    role: 'alert-rules',
    prometheus: $.prometheusName,
  },
  // versions are used by some CRs and reflected in labels.
  versions: std.parseYaml(importstr './versions.yaml')[0].versions,
  // In OSE images are overridden
  images: {
    alertmanager: 'quay.io/prometheus/alertmanager:v' + $.versions.alertmanager,
    prometheus: 'quay.io/prometheus/prometheus:v' + $.versions.prometheus,
    grafana: 'grafana/grafana:v' + $.versions.grafana,
    kubeStateMetrics: 'k8s.gcr.io/kube-state-metrics/kube-state-metrics:v' + $.versions.kubeStateMetrics,
    nodeExporter: 'quay.io/prometheus/node-exporter:v' + $.versions.nodeExporter,
    prometheusAdapter: 'directxman12/k8s-prometheus-adapter:v' + $.versions.prometheusAdapter,
    prometheusOperator: 'quay.io/prometheus-operator/prometheus-operator:v' + $.versions.prometheusOperator,
    prometheusOperatorReloader: 'quay.io/prometheus-operator/prometheus-config-reloader:v' + $.versions.prometheusOperator,
    promLabelProxy: 'quay.io/prometheuscommunity/prom-label-proxy:v' + $.versions.promLabelProxy,
    telemeter: '',
    thanos: 'quay.io/thanos/thanos:v' + $.versions.thanos,
    kubeRbacProxy: 'quay.io/brancz/kube-rbac-proxy:v' + $.versions.kubeRbacProxy,

    openshiftOauthProxy: 'quay.io/openshift/oauth-proxy:latest',
  },
  // Labels applied to every object
  commonLabels: {
    'app.kubernetes.io/part-of': 'openshift-monitoring',
  },
  // TLS Cipher suite applied to every component serving HTTPS traffic
  tlsCipherSuites: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305',
};

// objects deployed in openshift-monitoring namespace
local inCluster =
  {
    values+:: {
      common: commonConfig,

      // Configuration of all components
      clusterMonitoringOperator: {
        namespace: $.values.common.namespace,
        namespaceUserWorkload: $.values.common.namespaceUserWorkload,
        commonLabels+: $.values.common.commonLabels,
        mixin+: {
          ruleLabels: $.values.common.ruleLabels,
          _config+: {
            diskDeviceSelector: $.values.nodeExporter.mixin._config.diskDeviceSelector,
            namespaceSelector: $.values.common.mixinNamespaceSelector,
          },
        },
      },
      alertmanager: {
        name: 'main',
        namespace: $.values.common.namespace,
        version: $.values.common.versions.alertmanager,
        image: $.values.common.images.alertmanager,
        commonLabels+: $.values.common.commonLabels,
        tlsCipherSuites: $.values.common.tlsCipherSuites,
        mixin+: {
          ruleLabels: $.values.common.ruleLabels,
        },
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
        promLabelProxyImage: $.values.common.images.promLabelProxy,
      },
      grafana: {
        namespace: $.values.common.namespace,
        version: $.values.common.versions.grafana,
        image: $.values.common.images.grafana,
        commonLabels+: $.values.common.commonLabels,
        prometheusName: $.values.common.prometheusName,
        local allDashboards =
          $.nodeExporter.mixin.grafanaDashboards +
          $.prometheus.mixin.grafanaDashboards +
          $.controlPlane.mixin.grafanaDashboards +
          $.controlPlane.etcdMixin.grafanaDashboards,
        // Allow-listing dashboards that are going into the product. List needs to be sorted for std.setMember to work
        local includeDashboards = [
          'cluster-total.json',
          'etcd.json',
          'k8s-resources-cluster.json',
          'k8s-resources-namespace.json',
          'k8s-resources-node.json',
          'k8s-resources-pod.json',
          'k8s-resources-workload.json',
          'k8s-resources-workloads-namespace.json',
          'namespace-by-pod.json',
          'node-cluster-rsrc-use.json',
          'node-rsrc-use.json',
          'pod-total.json',
          'prometheus.json',
        ],
        dashboards: {
          [k]: allDashboards[k]
          for k in std.objectFields(allDashboards)
          if std.setMember(k, includeDashboards)
        },
        datasources: [{
          name: 'prometheus',
          type: 'prometheus',
          access: 'proxy',
          orgId: 1,
          url: 'https://prometheus-k8s.openshift-monitoring.svc:9091',
          version: 1,
          editable: false,
          basicAuth: true,
          basicAuthUser: 'internal',
          secureJsonData: {
            basicAuthPassword: '',
          },
          jsonData: {
            tlsSkipVerify: true,
          },
        }],
        config: {
          sections: {
            paths: {
              data: '/var/lib/grafana',
              logs: '/var/lib/grafana/logs',
              plugins: '/var/lib/grafana/plugins',
              provisioning: '/etc/grafana/provisioning',
            },
            server: {
              http_addr: '127.0.0.1',
              http_port: '3001',
            },
            security: {
              // OpenShift users are limited to 63 characters, with this we are
              // setting the Grafana user to something that can never be created
              // in OpenShift. This prevents users from getting proxied with an
              // identity that has superuser permissions in Grafana.
              admin_user: 'WHAT_YOU_ARE_DOING_IS_VOIDING_SUPPORT_0000000000000000000000000000000000000000000000000000000000000000',
              cookie_secure: true,
            },
            auth: {
              disable_login_form: true,
              disable_signout_menu: true,
            },
            'auth.basic': {
              enabled: false,
            },
            'auth.proxy': {
              enabled: true,
              header_name: 'X-Forwarded-User',
              auto_sign_up: true,
            },
            analytics: {
              reporting_enabled: false,
              check_for_updates: false,
            },
          },
        },
        tlsCipherSuites: $.values.common.tlsCipherSuites,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
      },
      kubeStateMetrics: {
        namespace: $.values.common.namespace,
        version: $.values.common.versions.kubeStateMetrics,
        image: $.values.common.images.kubeStateMetrics,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
        commonLabels+: $.values.common.commonLabels,
        mixin+: { ruleLabels: $.values.common.ruleLabels },
      },
      nodeExporter: {
        namespace: $.values.common.namespace,
        version: $.values.common.versions.nodeExporter,
        image: $.values.common.images.nodeExporter,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
        commonLabels+: $.values.common.commonLabels,
        mixin+: {
          ruleLabels: $.values.common.ruleLabels,
          _config+: {
            diskDeviceSelector: 'device=~"mmcblk.p.+|nvme.+|sd.+|vd.+|xvd.+|dm-.+|dasd.+"',
            rateInterval: '1m',  // adjust the rate interval value to be 4 x the node_exporter's scrape interval (15s).
          },
        },
      },
      openshiftStateMetrics: {
        namespace: $.values.common.namespace,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
        commonLabels+: $.values.common.commonLabels,
      },
      prometheus: {
        namespace: $.values.common.namespace,
        version: $.values.common.versions.prometheus,
        image: $.values.common.images.prometheus,
        commonLabels+: $.values.common.commonLabels,
        name: 'k8s',
        alertmanagerName: $.values.alertmanager.name,
        namespaces+: [
          'openshift-etcd',
          $.values.common.namespaceUserWorkload,
        ],
        namespaceSelector: $.values.common.clusterMonitoringNamespaceSelector,
        mixin+: {
          ruleLabels: $.values.common.ruleLabels,
          _config+: {
            prometheusSelector: 'job=~"prometheus-k8s|prometheus-user-workload"',
            thanosSelector: 'job=~"prometheus-(k8s|user-workload)-thanos-sidecar"',
          },
        },
        thanos: $.values.thanos {
          resources: {
            requests: {
              cpu: '1m',
              memory: '100Mi',
            },
          },
        },
        tlsCipherSuites: $.values.common.tlsCipherSuites,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
        promLabelProxyImage: $.values.common.images.promLabelProxy,
      },
      prometheusAdapter: {
        namespace: $.values.common.namespace,
        version: $.values.common.versions.prometheusAdapter,
        image: $.values.common.images.prometheusAdapter,
        prometheusURL: 'https://thanos-querier' + '.' + $.values.common.namespace + '.svc:9091',
        commonLabels+: $.values.common.commonLabels,
        tlsCipherSuites: $.values.common.tlsCipherSuites,
      },
      prometheusOperator: {
        namespace: $.values.common.namespace,
        version: $.values.common.versions.prometheusOperator,
        image: $.values.common.images.prometheusOperator,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
        configReloaderImage: $.values.common.images.prometheusOperatorReloader,
        commonLabels+: $.values.common.commonLabels,
        mixin+: {
          ruleLabels: $.values.common.ruleLabels,
          _config+: {
            prometheusOperatorSelector: 'job="prometheus-operator", namespace=~"%(namespace)s|%(namespaceUserWorkload)s"' % ($.values.common),
          },
        },
        tlsCipherSuites: $.values.common.tlsCipherSuites,
      },
      thanos: {
        image: $.values.common.images.thanos,
        version: $.values.common.versions.thanos,
      },
      thanosRuler: $.values.thanos {
        name: 'thanos-ruler',
        crName: 'user-workload',
        namespace: $.values.common.namespaceUserWorkload,
        replicas: 2,
        selectorLabels: {
          'app.kubernetes.io/name': 'thanos-ruler',
          'thanos-ruler': 'user-workload',
        },
        namespaceSelector: $.values.common.userWorkloadMonitoringNamespaceSelector,
        commonLabels+: $.values.common.commonLabels,
      },
      thanosQuerier: $.values.thanos {
        name: 'thanos-querier',
        namespace: $.values.common.namespace,
        replicas: 2,
        replicaLabels: ['prometheus_replica', 'thanos_ruler_replica'],
        stores: ['dnssrv+_grpc._tcp.prometheus-operated.openshift-monitoring.svc.cluster.local'],
        serviceMonitor: true,
        tlsCipherSuites: $.values.common.tlsCipherSuites,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
        promLabelProxyImage: $.values.common.images.promLabelProxy,
        commonLabels+: $.values.common.commonLabels,
      },
      telemeterClient: {
        namespace: $.values.common.namespace,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
        commonLabels+: $.values.common.commonLabels,
        tlsCipherSuites: $.values.common.tlsCipherSuites,
      },
      controlPlane: {
        namespace: $.values.common.namespace,
        commonLabels+: $.values.common.commonLabels,
        mixin+: {
          ruleLabels: $.values.common.ruleLabels,
          _config+: {
            diskDeviceSelector: $.values.nodeExporter.mixin._config.diskDeviceSelector,
            hostNetworkInterfaceSelector: 'device!~"veth.+"',
            kubeSchedulerSelector: 'job="scheduler"',
            namespaceSelector: $.values.common.mixinNamespaceSelector,
            cpuThrottlingSelector: $.values.common.mixinNamespaceSelector,
            kubeletPodLimit: 250,
          },
        },
      },
    },

    // Objects
    clusterMonitoringOperator: clusterMonitoringOperator($.values.clusterMonitoringOperator) {
      // The cluster-monitoring-operator ClusterRole needs the combined set of
      // permissions from all its operand ClusterRoles.  This extends the base
      // ClusterRole by just appending the rules from the others.
      clusterRole+: {
        rules+: inCluster.alertmanager.clusterRole.rules +
                inCluster.clusterMonitoringOperator.clusterRoleView.rules +
                inCluster.clusterMonitoringOperator.userWorkloadConfigEditRole.rules +
                inCluster.grafana.clusterRole.rules +
                inCluster.kubeStateMetrics.clusterRole.rules +
                inCluster.nodeExporter.clusterRole.rules +
                inCluster.openshiftStateMetrics.clusterRole.rules +
                inCluster.prometheusAdapter.clusterRole.rules +
                inCluster.prometheusAdapter.clusterRoleAggregatedMetricsReader.rules +
                inCluster.prometheusAdapter.clusterRoleServerResources.rules +
                inCluster.prometheus.clusterRole.rules +
                std.flatMap(function(role) role.rules,
                            inCluster.prometheus.roleSpecificNamespaces.items) +
                inCluster.prometheus.roleConfig.rules +
                inCluster.prometheusOperator.clusterRole.rules +
                inCluster.telemeterClient.clusterRole.rules +
                inCluster.thanosQuerier.clusterRole.rules +
                inCluster.thanosRuler.clusterRole.rules,
      },
    },
    alertmanager: alertmanager($.values.alertmanager),
    grafana: grafana($.values.grafana),
    kubeStateMetrics: kubeStateMetrics($.values.kubeStateMetrics),
    nodeExporter: nodeExporter($.values.nodeExporter),
    prometheus: prometheus($.values.prometheus),
    prometheusAdapter: prometheusAdapter($.values.prometheusAdapter),
    prometheusOperator: prometheusOperator($.values.prometheusOperator),
    controlPlane: controlPlane($.values.controlPlane),

    thanosRuler: thanosRuler($.values.thanosRuler),
    thanosQuerier: thanosQuerier($.values.thanosQuerier),

    telemeterClient: telemeterClient($.values.telemeterClient),
    openshiftStateMetrics: openshiftStateMetrics($.values.openshiftStateMetrics),
  } +
  (import './utils/anti-affinity.libsonnet') +
  (import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/addons/ksm-lite.libsonnet') +
  (import './utils/ibm-cloud-managed-profile.libsonnet') +
  (import './components/prometheus-adapter-audit.libsonnet') +
  {};  // Including empty object to simplify adding and removing imports during development

// objects deployed in openshift-user-workload-monitoring namespace
local userWorkload =
  {
    values:: {
      common: commonConfig {
        namespace: commonConfig.namespaceUserWorkload,
      },
      prometheus: {
        namespace: $.values.common.namespace,
        version: $.values.common.versions.prometheus,
        image: $.values.common.images.prometheus,
        name: 'user-workload',
        alertmanagerName: inCluster.values.alertmanager.name,
        commonLabels+: $.values.common.commonLabels,
        resources: {
          requests: { memory: '30Mi', cpu: '6m' },
        },
        namespaces: [$.values.common.namespaceUserWorkload],
        namespaceSelector: $.values.common.userWorkloadMonitoringNamespaceSelector,
        mixin+: {
          ruleLabels: $.values.common.ruleLabels,
          _config+: {
            prometheusSelector: 'job=~"prometheus-k8s|prometheus-user-workload"',
          },
        },
        thanos: inCluster.values.prometheus.thanos,
        tlsCipherSuites: $.values.common.tlsCipherSuites,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
      },
      prometheusOperator: {
        namespace: $.values.common.namespace,
        denyNamespace: inCluster.values.common.namespace,
        version: $.values.common.versions.prometheusOperator,
        image: $.values.common.images.prometheusOperator,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
        configReloaderImage: $.values.common.images.prometheusOperatorReloader,
        commonLabels+: $.values.common.commonLabels,
        mixin+: {
          ruleLabels: $.values.common.ruleLabels,
          _config+: {
            prometheusSelector: 'job=~"prometheus-k8s|prometheus-user-workload"',
          },
        },
      },
    },

    prometheus: prometheusUserWorkload($.values.prometheus),
    prometheusOperator: prometheusOperatorUserWorkload($.values.prometheusOperator),
  } +
  (import './utils/anti-affinity.libsonnet') +
  {};  // Including empty object to simplify adding and removing imports during development

// Manifestation
sanitizeAlertRules(addAnnotations(removeLimits(
  { ['alertmanager/' + name]: inCluster.alertmanager[name] for name in std.objectFields(inCluster.alertmanager) } +
  { ['cluster-monitoring-operator/' + name]: inCluster.clusterMonitoringOperator[name] for name in std.objectFields(inCluster.clusterMonitoringOperator) } +
  { ['grafana/' + name]: inCluster.grafana[name] for name in std.objectFields(inCluster.grafana) } +
  { ['kube-state-metrics/' + name]: inCluster.kubeStateMetrics[name] for name in std.objectFields(inCluster.kubeStateMetrics) } +
  { ['node-exporter/' + name]: inCluster.nodeExporter[name] for name in std.objectFields(inCluster.nodeExporter) } +
  { ['openshift-state-metrics/' + name]: inCluster.openshiftStateMetrics[name] for name in std.objectFields(inCluster.openshiftStateMetrics) } +
  { ['prometheus-k8s/' + name]: inCluster.prometheus[name] for name in std.objectFields(inCluster.prometheus) } +
  { ['prometheus-operator/' + name]: inCluster.prometheusOperator[name] for name in std.objectFields(inCluster.prometheusOperator) } +
  { ['prometheus-operator-user-workload/' + name]: userWorkload.prometheusOperator[name] for name in std.objectFields(userWorkload.prometheusOperator) } +
  { ['prometheus-user-workload/' + name]: userWorkload.prometheus[name] for name in std.objectFields(userWorkload.prometheus) } +
  { ['prometheus-adapter/' + name]: inCluster.prometheusAdapter[name] for name in std.objectFields(inCluster.prometheusAdapter) } +
  // needs to be removed once remote-write is allowed for sending telemetry
  { ['telemeter-client/' + name]: inCluster.telemeterClient[name] for name in std.objectFields(inCluster.telemeterClient) } +
  { ['thanos-querier/' + name]: inCluster.thanosQuerier[name] for name in std.objectFields(inCluster.thanosQuerier) } +
  { ['thanos-ruler/' + name]: inCluster.thanosRuler[name] for name in std.objectFields(inCluster.thanosRuler) } +
  { ['control-plane/' + name]: inCluster.controlPlane[name] for name in std.objectFields(inCluster.controlPlane) } +
  { ['manifests/' + name]: inCluster.manifests[name] for name in std.objectFields(inCluster.manifests) } +
  {}
)))
