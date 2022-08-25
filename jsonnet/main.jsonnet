local removeLimits = (import './utils/remove-limits.libsonnet').removeLimits;
local addAnnotations = (import './utils/add-annotations.libsonnet').addAnnotations;
local sanitizeAlertRules = (import './utils/sanitize-rules.libsonnet').sanitizeAlertRules;
local removeNetworkPolicy = (import './utils/remove-network-policy.libsonnet').removeNetworkPolicy;
local addBearerTokenToServiceMonitors = (import './utils/add-bearer-token-to-service-monitors.libsonnet').addBearerTokenToServiceMonitors;

local alertmanager = import './components/alertmanager.libsonnet';
local alertmanagerUserWorkload = import './components/alertmanager-user-workload.libsonnet';
local dashboards = import './components/dashboards.libsonnet';
local kubeStateMetrics = import './components/kube-state-metrics.libsonnet';
local controlPlane = import './components/control-plane.libsonnet';
local nodeExporter = import './components/node-exporter.libsonnet';
local prometheusAdapter = import './components/prometheus-adapter.libsonnet';
local prometheusOperator = import './components/prometheus-operator.libsonnet';
local admissionWebhook = import './components/admission-webhook.libsonnet';
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
    kubeStateMetrics: 'k8s.gcr.io/kube-state-metrics/kube-state-metrics:v' + $.versions.kubeStateMetrics,
    nodeExporter: 'quay.io/prometheus/node-exporter:v' + $.versions.nodeExporter,
    prometheusAdapter: 'directxman12/k8s-prometheus-adapter:v' + $.versions.prometheusAdapter,
    prometheusOperator: 'quay.io/prometheus-operator/prometheus-operator:v' + $.versions.prometheusOperator,
    prometheusOperatorReloader: 'quay.io/prometheus-operator/prometheus-config-reloader:v' + $.versions.prometheusOperator,
    prometheusOperatorAdmissionWebhook: 'quay.io/prometheus-operator/admission-webhook:v' + $.versions.prometheusOperator,
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
            hostNetworkInterfaceSelector: 'device!~"veth.+|tunbr"',
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
          _config+: {
            alertmanagerSelector: 'job=~"alertmanager-main|alertmanager-user-workload"',
          },
        },
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
        promLabelProxyImage: $.values.common.images.promLabelProxy,
      },
      dashboards: {
        namespace: $.values.common.namespace,
        commonLabels: {
          [k]: $.values.common.commonLabels[k]
          for k in std.objectFields($.values.common.commonLabels)
          // CMO doesn't deploy grafana hence version label not needed anymore
          if k != 'app.kubernetes.io/version'
        } + {
          'app.kubernetes.io/name': 'dashboard',
          'app.kubernetes.io/component': 'dashboard',
        },
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
        // This step is to delete row with titles 'Storage IO - Distribution(Containers)'
        // and 'Storage IO - Distribution' from 'k8s-resources-pod.json' dashboard since
        // Prometheus doesn't collect the per-container fs metrics
        local filteredDashboards = {
          'k8s-resources-pod.json': ['Storage IO - Distribution(Containers)', 'Storage IO - Distribution'],
        },
        local filterDashboard(dashboard, excludedRowTitles) = dashboard { rows: std.filter(function(row) !std.member(excludedRowTitles, row.title), dashboard.rows) },
        dashboards: {
          [k]: filterDashboard(allDashboards[k], if std.setMember(k, std.objectFields(filteredDashboards)) then filteredDashboards[k] else [])
          for k in std.objectFields(allDashboards)
          if std.setMember(k, includeDashboards)
        },
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
            thanos+: {
              sidecar+: {
                selector: 'job=~"prometheus-(k8s|user-workload)-thanos-sidecar"',
              },
            },
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
        additionalRelabelConfigs: {
          name: 'alert-relabel-configs',
          key: 'config.yaml',
          optional: true,
        },
      },
      prometheusAdapter: {
        namespace: $.values.common.namespace,
        version: $.values.common.versions.prometheusAdapter,
        image: $.values.common.images.prometheusAdapter,
        prometheusURL: 'https://prometheus-' + $.values.prometheus.name + '.' + $.values.common.namespace + '.svc:9091',
        commonLabels+: $.values.common.commonLabels,
        tlsCipherSuites: $.values.common.tlsCipherSuites,
      },
      admissionWebhook: {
        name: 'prometheus-operator-admission-webhook',
        namespace: $.values.common.namespace,
        version: $.values.common.versions.prometheusOperator,
        image: $.values.common.images.prometheusOperatorAdmissionWebhook,
        commonLabels+: $.values.common.commonLabels,
        tlsCipherSuites: $.values.common.tlsCipherSuites,
        resources: {
          requests: { cpu: '5m', memory: '30Mi' },
        },
      },
      prometheusOperator: {
        namespace: $.values.common.namespace,
        version: $.values.common.versions.prometheusOperator,
        image: $.values.common.images.prometheusOperator,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
        configReloaderImage: $.values.common.images.prometheusOperatorReloader,
        commonLabels+: $.values.common.commonLabels,
        conversionWebhook: {
          name: $.values.admissionWebhook.name,
          namespace: $.values.admissionWebhook.namespace,
          annotations+: {
            'service.beta.openshift.io/inject-cabundle': 'true',
          },
        },
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
            // Temporarily commented since upstream change https://github.com/kubernetes-monitoring/kubernetes-mixin/pull/767 not merged yet
            // diskDeviceSelector: $.values.nodeExporter.mixin._config.diskDeviceSelector,
            diskDeviceSelector: 'device=~"(/dev.+)|%s"' % std.join('|', ['mmcblk.p.+', 'nvme.+', 'rbd.+', 'sd.+', 'vd.+', 'xvd.+', 'dm-.+', 'dasd.+']),
            hostNetworkInterfaceSelector: 'device!~"veth.+"',
            kubeSchedulerSelector: 'job="scheduler"',
            namespaceSelector: $.values.common.mixinNamespaceSelector,
            cpuThrottlingSelector: $.values.common.mixinNamespaceSelector,
            kubeletPodLimit: 250,
            pvExcludedSelector: 'label_alerts_k8s_io_kube_persistent_volume_filling_up="disabled"',
            containerfsSelector: 'id!=""',
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
    dashboards: dashboards($.values.dashboards),
    kubeStateMetrics: kubeStateMetrics($.values.kubeStateMetrics),
    nodeExporter: nodeExporter($.values.nodeExporter),
    prometheus: prometheus($.values.prometheus),
    prometheusAdapter: prometheusAdapter($.values.prometheusAdapter),
    admissionWebhook: admissionWebhook($.values.admissionWebhook),
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
      alertmanager: {
        name: 'user-workload',
        namespace: $.values.common.namespace,
        version: $.values.common.versions.alertmanager,
        image: $.values.common.images.alertmanager,
        commonLabels+: $.values.common.commonLabels,
        tlsCipherSuites: $.values.common.tlsCipherSuites,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
        promLabelProxyImage: $.values.common.images.promLabelProxy,
        config: {
          route: {
            group_by: ['namespace'],
            receiver: 'Default',
          },
          receivers: [
            { name: 'Default' },
          ],
        },
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
      },
    },

    alertmanager: alertmanagerUserWorkload($.values.alertmanager),
    prometheus: prometheusUserWorkload($.values.prometheus),
    prometheusOperator: prometheusOperatorUserWorkload($.values.prometheusOperator),
  } +
  (import './utils/anti-affinity.libsonnet') +
  {};  // Including empty object to simplify adding and removing imports during development

// Manifestation
sanitizeAlertRules(addAnnotations(removeLimits(removeNetworkPolicy(
  // When the TLS certificate used for authentication gets rotated, Prometheus
  // doesn't pick up the new certificate until the connection to the target is
  // re-established. Because Prometheus uses keep-alive HTTP connections, the
  // consequence is that the scrapes start failing after about 1 day and the
  // TargetDown alert fires. To resolve the alert, the cluster admin has to
  // restart the pods being reported as down.
  //
  // To workaround the issue (and until Prometheus properly handles certificate
  // rotation), patch the service monitors in the openshift-monitoring and
  // openshift-user-workload-monitoring namespaces with fall-back authentication
  // method using the service account bearer token.
  //
  // Details in:
  // https://github.com/prometheus/prometheus/issues/9512 (upstream)
  // https://bugzilla.redhat.com/show_bug.cgi?id=2033575
  //
  // TODO(simonpasquier): once Prometheus issue #9512 is fixed downstream,
  // replace addBearerTokenToServiceMonitors() by
  // removeBearerTokenFromServiceMonitors() to ensure that all service monitors
  // use only TLS for authentication.
  addBearerTokenToServiceMonitors(
    { ['alertmanager/' + name]: inCluster.alertmanager[name] for name in std.objectFields(inCluster.alertmanager) } +
    { ['alertmanager-user-workload/' + name]: userWorkload.alertmanager[name] for name in std.objectFields(userWorkload.alertmanager) } +
    { ['cluster-monitoring-operator/' + name]: inCluster.clusterMonitoringOperator[name] for name in std.objectFields(inCluster.clusterMonitoringOperator) } +
    { ['dashboards/' + name]: inCluster.dashboards[name] for name in std.objectFields(inCluster.dashboards) } +
    { ['kube-state-metrics/' + name]: inCluster.kubeStateMetrics[name] for name in std.objectFields(inCluster.kubeStateMetrics) } +
    { ['node-exporter/' + name]: inCluster.nodeExporter[name] for name in std.objectFields(inCluster.nodeExporter) } +
    { ['openshift-state-metrics/' + name]: inCluster.openshiftStateMetrics[name] for name in std.objectFields(inCluster.openshiftStateMetrics) } +
    { ['prometheus-k8s/' + name]: inCluster.prometheus[name] for name in std.objectFields(inCluster.prometheus) } +
    { ['admission-webhook/' + name]: inCluster.admissionWebhook[name] for name in std.objectFields(inCluster.admissionWebhook) } +
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
  )
))))
