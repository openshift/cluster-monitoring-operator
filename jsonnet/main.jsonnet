local k = import 'ksonnet/ksonnet.beta.3/k.libsonnet';
local configmap = k.core.v1.configMap;
local removeLimits = (import 'remove-limits.libsonnet').removeLimits;
local kp = (import 'kube-prometheus/kube-prometheus.libsonnet') +
           (import 'kube-prometheus/kube-prometheus-anti-affinity.libsonnet') +
           (import 'kube-prometheus/kube-prometheus-static-etcd.libsonnet') +
           (import 'kube-prometheus/kube-prometheus-thanos-sidecar.libsonnet') +
           (import 'openshift-state-metrics/openshift-state-metrics.libsonnet') +
           {
             prometheusK8s+:: $.prometheus {
               // Openshift 4.0 clusters already have an etcd service and endpoints.
               // Additionally, the etcd client certificates secret should not be embedded in the
               // Cluster Monitoring Operator binary.
               // Hide these fields so they are not rendered as files.
               serviceEtcd:: super.serviceEtcd,
               endpointsEtcd:: super.endpointsEtcd,
               secretEtcdCerts:: super.secretEtcdCerts,
               serviceMonitorEtcd+: {
                 spec+: {
                   endpoints: [
                     {
                       port: 'etcd-metrics',
                       interval: '30s',
                       scheme: 'https',
                       tlsConfig: {
                         caFile: '/etc/prometheus/secrets/kube-etcd-client-certs/etcd-client-ca.crt',
                         keyFile: '/etc/prometheus/secrets/kube-etcd-client-certs/etcd-client.key',
                         certFile: '/etc/prometheus/secrets/kube-etcd-client-certs/etcd-client.crt',
                       },
                     },
                   ],
                 },
               },
             },
           } + {
             prometheusAlerts+:: {
               groups:
                 std.map(
                   function(ruleGroup)
                     if ruleGroup.name == 'etcd' then
                       ruleGroup { rules: std.filter(function(rule) !('alert' in rule && rule.alert == 'etcdHighNumberOfFailedGRPCRequests'), ruleGroup.rules) }
                     else if ruleGroup.name == 'kubernetes-system' then
                       ruleGroup { rules: std.filter(function(rule) !('alert' in rule && rule.alert == 'KubeVersionMismatch'), ruleGroup.rules) }
                     // Removing CPUThrottlingHigh alert as per https://bugzilla.redhat.com/show_bug.cgi?id=1843346
                     else if ruleGroup.name == 'kubernetes-resources' then
                       ruleGroup { rules: std.filter(function(rule) !('alert' in rule && rule.alert == 'CPUThrottlingHigh'), ruleGroup.rules) }
                     else if ruleGroup.name == 'prometheus' then
                       ruleGroup {
                         rules:
                           std.map(
                             function(rule)
                               if 'alert' in rule && (rule.alert == 'PrometheusDuplicateTimestamps' || rule.alert == 'PrometheusOutOfOrderTimestamps') then
                                 rule { 'for': '1h' }
                               else
                                 rule,
                             ruleGroup.rules,
                           ),
                       }
                     else
                       ruleGroup,
                   super.groups,
                 ),
             },
           } +
           (import 'telemeter-client/client.libsonnet') +
           {

             _config+:: {
               imageRepos+:: {
                 openshiftOauthProxy: 'quay.io/openshift/oauth-proxy',
                 prometheus: 'openshift/prometheus',
                 alertmanager: 'openshift/prometheus-alertmanager',
                 nodeExporter: 'openshift/prometheus-node-exporter',
                 promLabelProxy: 'quay.io/coreos/prom-label-proxy',
                 kubeRbacProxy: 'quay.io/coreos/kube-rbac-proxy',
                 prometheusAdapter: 'quay.io/coreos/k8s-prometheus-adapter-amd64',
                 openshiftThanos: 'quay.io/openshift/origin-thanos',
               },
               versions+:: {
                 // Because we build OpenShift images separately to upstream,
                 // we have to ensure these versions exist before upgrading.
                 openshiftOauthProxy: 'latest',
                 prometheus: 'v2.15.2',
                 alertmanager: 'v0.20.0',
                 nodeExporter: 'v0.18.1',
                 promLabelProxy: 'v0.1.0',
                 kubeRbacProxy: 'v0.4.1',
                 prometheusAdapter: 'v0.4.1',
                 openshiftThanos: 'latest',
               },
               prometheusAdapter+:: {
                 prometheusURL: 'https://prometheus-k8s.openshift-monitoring.svc:9091',
               },
               etcd+:: {
                 ips: [],
                 clientCA: '',
                 clientKey: '',
                 clientCert: '',
                 serverName: '',
               },
               prometheus+:: {
                 namespaces+: [
                   'openshift-etcd',
                   'openshift-user-workload-monitoring',
                 ],
               },
             },
             telemeterClient+:: {
               trustedCaBundle:
                 configmap.new('telemeter-trusted-ca-bundle', { 'ca-bundle.crt': '' }) +
                 configmap.mixin.metadata.withNamespace($._config.namespace) +
                 configmap.mixin.metadata.withLabels({ 'config.openshift.io/inject-trusted-cabundle': 'true' }),
             },
           } +
           (import 'rules.jsonnet') +
           (import 'prometheus-operator.jsonnet') +
           (import 'prometheus-operator-user-workload.jsonnet') +
           (import 'node-exporter.jsonnet') +
           (import 'kube-state-metrics.jsonnet') +
           (import 'grafana.jsonnet') +
           (import 'alertmanager.jsonnet') +
           (import 'prometheus.jsonnet') +
           (import 'prometheus-user-workload.jsonnet') +
           (import 'prometheus-adapter.jsonnet') +
           (import 'cluster-monitoring-operator.jsonnet') +
           (import 'thanos-querier.jsonnet') +
           (import 'thanos-ruler.jsonnet') +
           (import 'remove-runbook.libsonnet') + {
  _config+:: {
    namespace: 'openshift-monitoring',
    namespaceUserWorkload: 'openshift-user-workload-monitoring',

    hostNetworkInterfaceSelector: 'device!~"veth.+"',

    kubeSchedulerSelector: 'job="scheduler"',

    namespaceSelector: 'namespace=~"(openshift-.*|kube-.*|default|logging)"',
    cpuThrottlingSelector: 'namespace=~"(openshift-.*|kube-.*|default|logging)"',

    prometheusSelector: 'job=~"prometheus-k8s|prometheus-user-workload"',

    kubeletPodLimit: 250,

    // Certificates are issued for 4h.
    certExpirationWarningSeconds: 90 * 60,  // 1.5h
    certExpirationCriticalSeconds: 60 * 60,  // 1h
  },
} + {
  local d = super.grafanaDashboards,
  grafanaDashboards:: {
    [k]: d[k]
    for k in std.objectFields(d)
    // This array must be sorted for `std.setMember` to work.
    if !std.setMember(k, ['apiserver.json', 'controller-manager.json', 'kubelet.json', 'namespace-by-pod.json', 'namespace-by-workload.json', 'nodes.json', 'persistentvolumesusage.json', 'pod-total.json', 'pods.json', 'prometheus-remote-write.json', 'proxy.json', 'scheduler.json', 'statefulset.json', 'workload-total.json'])
  },
} + {
  _config+:: {
    local j = super.jobs,
    jobs: {
      [k]: j[k]
      for k in std.objectFields(j)
      if !std.setMember(k, ['CoreDNS', 'TelemeterClient'])
    },
  },
} + {
  _config+:: {
    openshiftStateMetricsSelector: 'job="openshift-state-metrics"',
    jobs+:: { OpenShiftStateMetrics: $._config.openshiftStateMetricsSelector },
  },
};

removeLimits(
  { ['prometheus-operator/' + name]: kp.clusterPrometheusOperator[name] for name in std.objectFields(kp.clusterPrometheusOperator) } +
  { ['prometheus-operator-user-workload/' + name]: kp.prometheusOperatorUserWorkload[name] for name in std.objectFields(kp.prometheusOperatorUserWorkload) } +
  { ['node-exporter/' + name]: kp.nodeExporter[name] for name in std.objectFields(kp.nodeExporter) } +
  { ['kube-state-metrics/' + name]: kp.kubeStateMetrics[name] for name in std.objectFields(kp.kubeStateMetrics) } +
  { ['openshift-state-metrics/' + name]: kp.openshiftStateMetrics[name] for name in std.objectFields(kp.openshiftStateMetrics) } +
  { ['alertmanager/' + name]: kp.alertmanager[name] for name in std.objectFields(kp.alertmanager) } +
  { ['prometheus-k8s/' + name]: kp.prometheusK8s[name] for name in std.objectFields(kp.prometheusK8s) } +
  { ['prometheus-user-workload/' + name]: kp.prometheusUserWorkload[name] for name in std.objectFields(kp.prometheusUserWorkload) } +
  { ['prometheus-adapter/' + name]: kp.prometheusAdapter[name] for name in std.objectFields(kp.prometheusAdapter) } +
  { ['grafana/' + name]: kp.grafana[name] for name in std.objectFields(kp.grafana) } +
  // needs to be removed once 4.4 ships, as this is needed for removal of the
  // manifests, as part of the migration to using remote-write for sending
  // telemetry.
  { ['telemeter-client/' + name]: kp.telemeterClient[name] for name in std.objectFields(kp.telemeterClient) } +
  { ['cluster-monitoring-operator/' + name]: kp.clusterMonitoringOperator[name] for name in std.objectFields(kp.clusterMonitoringOperator) } +
  { ['thanos-querier/' + name]: kp.thanos.querier[name] for name in std.objectFields(kp.thanos.querier) } +
  { ['thanos-ruler/' + name]: kp.thanos.ruler[name] for name in std.objectFields(kp.thanos.ruler) }
)
