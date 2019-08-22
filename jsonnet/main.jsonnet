local k = import 'ksonnet/ksonnet.beta.3/k.libsonnet';
local configmap = k.core.v1.configMap;
local removeLimits = (import 'remove-limits.libsonnet').removeLimits;
local kp = (import 'kube-prometheus/kube-prometheus.libsonnet') +
           (import 'kube-prometheus/kube-prometheus-anti-affinity.libsonnet') +
           (import 'kube-prometheus/kube-prometheus-static-etcd.libsonnet') +
           (import 'openshift-state-metrics/openshift-state-metrics.libsonnet') +
           {
             prometheus+:: {
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
               },
               versions+:: {
                 // Because we build OpenShift images separately to upstream,
                 // we have to ensure these versions exist before upgrading.
                 openshiftOauthProxy: 'latest',
                 prometheus: 'v2.7.1',
                 alertmanager: 'v0.15.2',
                 nodeExporter: 'v0.16.0',
                 promLabelProxy: 'v0.1.0',
                 kubeRbacProxy: 'v0.4.1',
                 prometheusAdapter: 'v0.4.1',
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
                   'openshift-apiserver',
                   'openshift-kube-scheduler',
                   'openshift-kube-controller-manager',
                   'openshift-etcd',
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
           (import 'node-exporter.jsonnet') +
           (import 'kube-state-metrics.jsonnet') +
           (import 'grafana.jsonnet') +
           (import 'alertmanager.jsonnet') +
           (import 'prometheus.jsonnet') +
           (import 'prometheus-adapter.jsonnet') +
           (import 'cluster-monitoring-operator.jsonnet') +
           (import 'remove-runbook.libsonnet') + {
  _config+:: {
    namespace: 'openshift-monitoring',

    hostNetworkInterfaceSelector: 'device!~"veth.+"',

    kubeSchedulerSelector: 'job="scheduler"',

    namespaceSelector: 'namespace=~"(openshift-.*|kube-.*|default|logging)"',

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
    if !std.setMember(k, ['apiserver.json', 'controller-manager.json', 'kubelet.json', 'nodes.json', 'persistentvolumesusage.json', 'pods.json', 'proxy.json', 'scheduler.json', 'statefulset.json'])
  },
} + {
  _config+:: {
    local j = super.jobs,
    jobs: {
      [k]: j[k]
      for k in std.objectFields(j)
      if !std.setMember(k, ['CoreDNS'])
    },
  },
} + {
  _config+:: {
    openshiftStateMetricsSelector: 'job="openshift-state-metrics"',
    jobs+:: { OpenShiftStateMetrics: $._config.openshiftStateMetricsSelector },
  },
};

removeLimits(
  { ['prometheus-operator/' + name]: kp.prometheusOperator[name] for name in std.objectFields(kp.prometheusOperator) } +
  { ['node-exporter/' + name]: kp.nodeExporter[name] for name in std.objectFields(kp.nodeExporter) } +
  { ['kube-state-metrics/' + name]: kp.kubeStateMetrics[name] for name in std.objectFields(kp.kubeStateMetrics) } +
  { ['openshift-state-metrics/' + name]: kp.openshiftStateMetrics[name] for name in std.objectFields(kp.openshiftStateMetrics) } +
  { ['alertmanager/' + name]: kp.alertmanager[name] for name in std.objectFields(kp.alertmanager) } +
  { ['prometheus-k8s/' + name]: kp.prometheus[name] for name in std.objectFields(kp.prometheus) } +
  { ['prometheus-adapter/' + name]: kp.prometheusAdapter[name] for name in std.objectFields(kp.prometheusAdapter) } +
  { ['grafana/' + name]: kp.grafana[name] for name in std.objectFields(kp.grafana) } +
  { ['telemeter-client/' + name]: kp.telemeterClient[name] for name in std.objectFields(kp.telemeterClient) } +
  { ['cluster-monitoring-operator/' + name]: kp.clusterMonitoringOperator[name] for name in std.objectFields(kp.clusterMonitoringOperator) }
)
