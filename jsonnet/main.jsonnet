local removeLimits = (import './utils/remove-limits.libsonnet').removeLimits;
local addAnnotations = (import './utils/add-annotations.libsonnet').addAnnotations;
local addLabels = (import './utils/add-labels.libsonnet').addLabels;
local sanitizeAlertRules = (import './utils/sanitize-rules.libsonnet').sanitizeAlertRules;
local removeImageLocations = (import './utils/remove-images.libsonnet').removeImageLocations;
local removeNetworkPolicy = (import './utils/remove-network-policy.libsonnet').removeNetworkPolicy;
local configureAuthenticationForMonitors = (import './utils/configure-authentication-for-monitors.libsonnet').configureAuthenticationForMonitors;
local setTerminationMessagePolicy = (import './utils/set-terminationMessagePolicy.libsonnet').setTerminationMessagePolicy;

local alertmanager = import './components/alertmanager.libsonnet';
local alertmanagerUserWorkload = import './components/alertmanager-user-workload.libsonnet';
local kubeStateMetrics = import './components/kube-state-metrics.libsonnet';
local controlPlane = import './components/control-plane.libsonnet';
local nodeExporter = import './components/node-exporter.libsonnet';
local metricsServer = import './components/metrics-server.libsonnet';
local prometheusOperator = import './components/prometheus-operator.libsonnet';
local admissionWebhook = import './components/admission-webhook.libsonnet';
local prometheusOperatorUserWorkload = import './components/prometheus-operator-user-workload.libsonnet';
local prometheus = import './components/prometheus.libsonnet';
local prometheusUserWorkload = import './components/prometheus-user-workload.libsonnet';
local clusterMonitoringOperator = import './components/cluster-monitoring-operator.libsonnet';
local monitoringPlugin = import './components/monitoring-plugin.libsonnet';

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
  userWorkloadMonitoringResourceSelector: {
    matchExpressions: [
      {
        key: 'openshift.io/user-monitoring',
        operator: 'NotIn',
        values: ['false'],
      },
    ],
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
    kubeStateMetrics: 'registry.k8s.io/kube-state-metrics/kube-state-metrics:v' + $.versions.kubeStateMetrics,
    nodeExporter: 'quay.io/prometheus/node-exporter:v' + $.versions.nodeExporter,
    kubernetesMetricsServer: 'registry.k8s.io/metrics-server/metrics-server:v' + $.versions.kubernetesMetricsServer,
    prometheusOperator: 'quay.io/prometheus-operator/prometheus-operator:v' + $.versions.prometheusOperator,
    prometheusOperatorReloader: 'quay.io/prometheus-operator/prometheus-config-reloader:v' + $.versions.prometheusOperator,
    prometheusOperatorAdmissionWebhook: 'quay.io/prometheus-operator/admission-webhook:v' + $.versions.prometheusOperator,
    promLabelProxy: 'quay.io/prometheuscommunity/prom-label-proxy:v' + $.versions.promLabelProxy,
    telemeter: '',
    thanos: 'quay.io/thanos/thanos:v' + $.versions.thanos,
    kubeRbacProxy: 'quay.io/brancz/kube-rbac-proxy:v' + $.versions.kubeRbacProxy,
    monitoringPlugin: 'quay.io/openshift/origin-monitoring-plugin:' + $.versions.monitoringPlugin,
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
        config: {
          // When a cluster-wide proxy is used, CMO injects the needed
          // environment variables into the Alertmanager container.
          global+: {
            http_config+: {
              proxy_from_environment: true,
            },
          },
          inhibit_rules: [{
            source_matchers: ['severity = critical'],
            target_matchers: ['severity =~ warning|info'],
            equal: ['namespace', 'alertname'],
          }, {
            source_matchers: ['severity = warning'],
            target_matchers: ['severity = info'],
            equal: ['namespace', 'alertname'],
          }],
          route: {
            group_by: ['namespace'],
            group_wait: '30s',
            group_interval: '5m',
            repeat_interval: '12h',
            receiver: 'Default',
            routes: [
              { receiver: 'Watchdog', matchers: ['alertname = Watchdog'] },
              { receiver: 'Critical', matchers: ['severity = critical'] },
            ],
          },
          receivers: [
            { name: 'Default' },
            { name: 'Watchdog' },
            { name: 'Critical' },
          ],
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
            fsMountpointSelector: 'mountpoint!~"/var/lib/ibmc-s3fs.*"',
          },
        },
        // The list of ignored devices is replaced by the Cluster Monitoring Operator (CMO) at runtime depending on the configuration of the CMO.
        ignoredNetworkDevices:: '^.*$',
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
          $.values.common.namespaceUserWorkload,
        ],
        namespaceSelector: $.values.common.clusterMonitoringNamespaceSelector,
        serviceDiscoveryRole: 'Endpoints',
        mixin+: {
          ruleLabels: $.values.common.ruleLabels,
          _config+: {
            showMultiCluster: false,
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
      metricsServer: {
        namespace: $.values.common.namespace,
        version: $.values.common.versions.kubernetesMetricsServer,
        image: $.values.common.images.kubernetesMetricsServer,
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
        tlsSecretName: 'prometheus-operator-admission-webhook-tls',
        port: 8443,
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
        resourceSelector: $.values.common.userWorkloadMonitoringResourceSelector,
        namespaceSelector: $.values.common.userWorkloadMonitoringNamespaceSelector,
        commonLabels+: $.values.common.commonLabels,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
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
        securityContext: {
          runAsNonRoot: true,
          seccompProfile: { type: 'RuntimeDefault' },
        },
        securityContextContainer: {
          runAsNonRoot: true,
          seccompProfile: { type: 'RuntimeDefault' },
          allowPrivilegeEscalation: false,
          readOnlyRootFilesystem: true,
          capabilities: { drop: ['ALL'] },
        },
      },
      telemeterClient: {
        namespace: $.values.common.namespace,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
        commonLabels+: $.values.common.commonLabels,
        tlsCipherSuites: $.values.common.tlsCipherSuites,
      },
      monitoringPlugin: {
        namespace: $.values.common.namespace,
        commonLabels+: $.values.common.commonLabels,
        image: $.values.common.images.monitoringPlugin,
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
            showMultiCluster: false,  // Opt-out of multi-cluster rules (opted-in by midstream kube-prometheus)
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
                inCluster.clusterMonitoringOperator.clusterRoleAggregatedMetricsReader.rules +
                inCluster.clusterMonitoringOperator.clusterRolePodMetricsReader.rules +
                inCluster.kubeStateMetrics.clusterRole.rules +
                inCluster.nodeExporter.clusterRole.rules +
                inCluster.openshiftStateMetrics.clusterRole.rules +
                inCluster.metricsServer.clusterRole.rules +
                inCluster.prometheus.clusterRole.rules +
                std.flatMap(function(role) role.rules,
                            inCluster.prometheus.roleSpecificNamespaces.items) +
                inCluster.prometheus.roleConfig.rules +
                inCluster.prometheusOperator.clusterRole.rules +
                inCluster.telemeterClient.clusterRole.rules +
                inCluster.thanosQuerier.clusterRole.rules +
                inCluster.thanosRuler.clusterRole.rules +
                [],
      },
    },
    alertmanager: alertmanager($.values.alertmanager),
    kubeStateMetrics: kubeStateMetrics($.values.kubeStateMetrics),
    nodeExporter: nodeExporter($.values.nodeExporter),
    prometheus: prometheus($.values.prometheus),
    metricsServer: metricsServer($.values.metricsServer),
    admissionWebhook: admissionWebhook($.values.admissionWebhook),
    prometheusOperator: prometheusOperator($.values.prometheusOperator),
    controlPlane: controlPlane($.values.controlPlane),

    thanosRuler: thanosRuler($.values.thanosRuler),
    thanosQuerier: thanosQuerier($.values.thanosQuerier),

    telemeterClient: telemeterClient($.values.telemeterClient),
    monitoringPlugin: monitoringPlugin($.values.monitoringPlugin),
    openshiftStateMetrics: openshiftStateMetrics($.values.openshiftStateMetrics),
  } +
  (import './utils/anti-affinity.libsonnet') +
  (import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/addons/ksm-lite.libsonnet') +
  (import './utils/ibm-cloud-managed-profile.libsonnet') +
  (import './components/metrics-server-audit.libsonnet') +
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
          // When a cluster-wide proxy is used, CMO injects the needed
          // environment variables into the Alertmanager container.
          global+: {
            http_config+: {
              proxy_from_environment: true,
            },
          },
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
        resourceSelector: $.values.common.userWorkloadMonitoringResourceSelector,
        namespaceSelector: $.values.common.userWorkloadMonitoringNamespaceSelector,
        thanos: inCluster.values.prometheus.thanos,
        tlsCipherSuites: $.values.common.tlsCipherSuites,
        kubeRbacProxyImage: $.values.common.images.kubeRbacProxy,
        serviceDiscoveryRole: 'Endpoints',
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
setTerminationMessagePolicy(
  addLabels(
    commonConfig.commonLabels,
    addAnnotations(
      sanitizeAlertRules(
        removeImageLocations(
          removeLimits(
            removeNetworkPolicy(
              // Enforce mTLS authentication + disable usage of bearer token for all service/pod monitors.
              // See https://issues.redhat.com/browse/OCPBUGS-4184 for details.
              configureAuthenticationForMonitors(
                { ['alertmanager/' + name]: inCluster.alertmanager[name] for name in std.objectFields(inCluster.alertmanager) } +
                { ['alertmanager-user-workload/' + name]: userWorkload.alertmanager[name] for name in std.objectFields(userWorkload.alertmanager) } +
                { ['cluster-monitoring-operator/' + name]: inCluster.clusterMonitoringOperator[name] for name in std.objectFields(inCluster.clusterMonitoringOperator) } +
                { ['kube-state-metrics/' + name]: inCluster.kubeStateMetrics[name] for name in std.objectFields(inCluster.kubeStateMetrics) } +
                { ['node-exporter/' + name]: inCluster.nodeExporter[name] for name in std.objectFields(inCluster.nodeExporter) } +
                { ['openshift-state-metrics/' + name]: inCluster.openshiftStateMetrics[name] for name in std.objectFields(inCluster.openshiftStateMetrics) } +
                { ['prometheus-k8s/' + name]: inCluster.prometheus[name] for name in std.objectFields(inCluster.prometheus) } +
                { ['admission-webhook/' + name]: inCluster.admissionWebhook[name] for name in std.objectFields(inCluster.admissionWebhook) } +
                { ['prometheus-operator/' + name]: inCluster.prometheusOperator[name] for name in std.objectFields(inCluster.prometheusOperator) } +
                { ['prometheus-operator-user-workload/' + name]: userWorkload.prometheusOperator[name] for name in std.objectFields(userWorkload.prometheusOperator) } +
                { ['prometheus-user-workload/' + name]: userWorkload.prometheus[name] for name in std.objectFields(userWorkload.prometheus) } +
                { ['metrics-server/' + name]: inCluster.metricsServer[name] for name in std.objectFields(inCluster.metricsServer) } +
                // needs to be removed once remote-write is allowed for sending telemetry
                { ['telemeter-client/' + name]: inCluster.telemeterClient[name] for name in std.objectFields(inCluster.telemeterClient) } +
                { ['monitoring-plugin/' + name]: inCluster.monitoringPlugin[name] for name in std.objectFields(inCluster.monitoringPlugin) } +
                { ['thanos-querier/' + name]: inCluster.thanosQuerier[name] for name in std.objectFields(inCluster.thanosQuerier) } +
                { ['thanos-ruler/' + name]: inCluster.thanosRuler[name] for name in std.objectFields(inCluster.thanosRuler) } +
                { ['control-plane/' + name]: inCluster.controlPlane[name] for name in std.objectFields(inCluster.controlPlane) } +
                { ['manifests/' + name]: inCluster.manifests[name] for name in std.objectFields(inCluster.manifests) } +
                {}
              )
            )
          )
        )
      )
    )
  ),
)
