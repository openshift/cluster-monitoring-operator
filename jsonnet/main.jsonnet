local removeLimits = (import 'remove-limits.libsonnet').removeLimits;
local addReleaseAnnotation = (import 'add-release-annotation.libsonnet').addReleaseAnnotation;
local addWorkloadAnnotation = (import 'add-workload-annotation.libsonnet').addWorkloadAnnotation;
local excludeRules = (import 'patch-rules.libsonnet').excludeRules;
local patchRules = (import 'patch-rules.libsonnet').patchRules;
local removeRunbookUrl = (import 'remove-runbook-urls.libsonnet').removeRunbookUrl;

local alertmanager = import './alertmanager.libsonnet';
local grafana = import './grafana.libsonnet';
local kubeStateMetrics = import './kube-state-metrics.libsonnet';
local controlPlane = import './control-plane.libsonnet';
local nodeExporter = import './node-exporter.libsonnet';
local prometheusAdapter = import './prometheus-adapter.libsonnet';
local prometheusOperator = import './prometheus-operator.libsonnet';
local prometheusOperatorUserWorkload = import './prometheus-operator-user-workload.libsonnet';
local prometheus = import './prometheus.libsonnet';
local prometheusUserWorkload = import './prometheus-user-workload.libsonnet';
local clusterMonitoringOperator = import './cluster-monitoring-operator.libsonnet';
local ibmCloudManagedProfile = import 'ibm-cloud-managed-profile.libsonnet';

local thanosRuler = import './thanos-ruler.libsonnet';
local thanosQuerier = import './thanos-querier.libsonnet';

local openshiftStateMetrics = import './openshift-state-metrics.libsonnet';
local telemeterClient = import './telemeter-client.libsonnet';

/*
TODO(paulfantom):
- thanos sidecar inclusion - needs https://github.com/prometheus-operator/kube-prometheus/pull/909
- grafana config - needs https://github.com/prometheus-operator/kube-prometheus/pull/907
*/

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
    ],
  },
  prometheusName: 'k8s',
  ruleLabels: {
    role: 'alert-rules',
    prometheus: $.prometheusName,
  },
  // versions are used by some CRs and reflected in labels.
  versions: {
    alertmanager: '0.21.0',
    prometheus: '2.26.0',
    grafana: '7.5.4',
    kubeStateMetrics: '2.0.0',
    nodeExporter: '1.1.2',
    prometheusAdapter: '0.8.4',
    prometheusOperator: '0.48.1',
    promLabelProxy: '0.2.0',
    thanos: '0.20.2',
  },
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
    promLabelProxy: 'quay.io/prometheuscommunity/prom-label-proxy:v' + $.versions.thanos,
    telemeter: '',
    thanos: 'quay.io/thanos/thanos:v' + $.versions.thanos,

    openshiftOauthProxy: 'quay.io/openshift/oauth-proxy:latest',
    //kubeRbacProxy: 'quay.io/brancz/kube-rbac-proxy:v0.8.0',
  },
  // Labels applied to every object
  commonLabels: {
    'app.kubernetes.io/part-of': 'openshift-monitoring',
  },
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
          },
        },
      },
      alertmanager: {
        name: 'main',
        namespace: $.values.common.namespace,
        version: $.values.common.versions.alertmanager,
        image: $.values.common.images.alertmanager,
        commonLabels+: $.values.common.commonLabels,
        mixin+: { ruleLabels: $.values.common.ruleLabels },
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
          basicAuthPassword: '',
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
      },
      kubeStateMetrics: {
        namespace: $.values.common.namespace,
        version: $.values.common.versions.kubeStateMetrics,
        image: $.values.common.images.kubeStateMetrics,
        commonLabels+: $.values.common.commonLabels,
        mixin+: { ruleLabels: $.values.common.ruleLabels },
      },
      nodeExporter: {
        namespace: $.values.common.namespace,
        version: $.values.common.versions.nodeExporter,
        image: $.values.common.images.nodeExporter,
        commonLabels+: $.values.common.commonLabels,
        mixin+: {
          ruleLabels: $.values.common.ruleLabels,
          _config+: {
            diskDeviceSelector: 'device=~"mmcblk.p.+|nvme.+|sd.+|vd.+|xvd.+|dm-.+|dasd.+"',
          },
        },
      },
      openshiftStateMetrics: {
        namespace: $.values.common.namespace,
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
        thanos: $.values.thanosSidecar,
      },
      prometheusAdapter: {
        namespace: $.values.common.namespace,
        version: $.values.common.versions.prometheusAdapter,
        image: $.values.common.images.prometheusAdapter,
        prometheusURL: 'https://prometheus-' + $.values.prometheus.name + '.' + $.values.common.namespace + '.svc:9091',
        commonLabels+: $.values.common.commonLabels,
      },
      prometheusOperator: {
        namespace: $.values.common.namespace,
        version: $.values.common.versions.prometheusOperator,
        image: $.values.common.images.prometheusOperator,
        configReloaderImage: $.values.common.images.prometheusOperatorReloader,
        commonLabels+: $.values.common.commonLabels,
        mixin+: {
          ruleLabels: $.values.common.ruleLabels,
          _config+: {
            prometheusSelector: 'job=~"prometheus-k8s|prometheus-user-workload"',
          },
        },
      },
      thanos: {
        image: $.values.common.images.thanos,
        version: $.values.common.versions.thanos,
      },
      thanosSidecar:: $.values.thanos {
        resources: {
          requests: {
            cpu: '1m',
            memory: '100Mi',
          },
        },
      },
      thanosRuler: $.values.thanos {
        name: 'user-workload',
        namespace: $.values.common.namespaceUserWorkload,
        labels: {
          'app.kubernetes.io/name': 'user-workload',
        },
        selectorLabels: {
          app: 'thanos-ruler',
          'thanos-ruler': 'user-workload',
        },
        ports: {
          web: 9091,
          grpc: 10901,
        },
        namespaceSelector: $.values.common.userWorkloadMonitoringNamespaceSelector,
      },
      thanosQuerier: $.values.thanos {
        name: 'thanos-querier',
        namespace: $.values.common.namespace,
        replicas: 2,
        replicaLabels: ['prometheus_replica', 'thanos_ruler_replica'],
        stores: ['dnssrv+_grpc._tcp.prometheus-operated.openshift-monitoring.svc.cluster.local'],
        serviceMonitor: true,
      },
      telemeterClient: {
        namespace: $.values.common.namespace,
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
            namespaceSelector: 'namespace=~"(openshift-.*|kube-.*|default|logging)"',
            cpuThrottlingSelector: 'namespace=~"(openshift-.*|kube-.*|default|logging)"',
            kubeletPodLimit: 250,
          },
        },
      },
    },

    // Objects
    clusterMonitoringOperator: clusterMonitoringOperator($.values.clusterMonitoringOperator),
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
  (import './anti-affinity.libsonnet') +
  (import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/addons/ksm-lite.libsonnet') +
  ibmCloudManagedProfile +
  {};

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
        thanos: inCluster.values.thanosSidecar,
      },
      prometheusOperator: {
        namespace: $.values.common.namespace,
        denyNamespace: inCluster.values.common.namespace,
        version: $.values.common.versions.prometheusOperator,
        image: $.values.common.images.prometheusOperator,
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
  (import './anti-affinity.libsonnet') +
  {};

// Manifestation
// TODO(paulfantom): removeRunbookUrl, excludeRules, and patchRules should be converted into sanitizeRules() function
removeRunbookUrl(patchRules(excludeRules(addWorkloadAnnotation(addReleaseAnnotation(removeLimits(
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
))))))
