local utils = import 'kubernetes-mixin/lib/utils.libsonnet';
local kp = (import 'kube-prometheus/kube-prometheus.libsonnet') +
           // NOTE: the `anti-affinity` package is actually the
           // `kube-prometheus` package checked out at a specific version
           // that includes https://github.com/coreos/prometheus-operator/pull/1935.
           (import 'anti-affinity/kube-prometheus-anti-affinity.libsonnet') +
           (import 'kube-prometheus/kube-prometheus-static-etcd.libsonnet') +
           {
             _config+:: {

               tlsCipherSuites: [
                 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',  // required by h2: http://golang.org/cl/30721
                 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',  // required by h2: http://golang.org/cl/30721

                 // 'TLS_RSA_WITH_RC4_128_SHA',            // insecure: https://access.redhat.com/security/cve/cve-2013-2566
                 // 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',       // insecure: https://access.redhat.com/articles/2548661
                 // 'TLS_RSA_WITH_AES_128_CBC_SHA',        // disabled by h2
                 // 'TLS_RSA_WITH_AES_256_CBC_SHA',        // disabled by h2
                 'TLS_RSA_WITH_AES_128_CBC_SHA256',
                 // 'TLS_RSA_WITH_AES_128_GCM_SHA256',     // disabled by h2
                 // 'TLS_RSA_WITH_AES_256_GCM_SHA384',     // disabled by h2
                 // 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',    // insecure: https://access.redhat.com/security/cve/cve-2013-2566
                 // 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',// disabled by h2
                 // 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',// disabled by h2
                 // 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',      // insecure: https://access.redhat.com/security/cve/cve-2013-2566
                 // 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', // insecure: https://access.redhat.com/articles/2548661
                 // 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',  // disabled by h2
                 // 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',  // disabled by h2
                 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
                 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',

                 // disabled by h2 means: https://github.com/golang/net/blob/e514e69ffb8bc3c76a71ae40de0118d794855992/http2/ciphers.go

                 // 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',   // TODO: Might not work with h2
                 // 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', // TODO: Might not work with h2
                 // 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305',    // TODO: Might not work with h2
                 // 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305',  // TODO: Might not work with h2
               ],

               imageRepos+:: {
                 openshiftOauthProxy: 'openshift/oauth-proxy',
                 prometheus: 'openshift/prometheus',
                 alertmanager: 'openshift/prometheus-alertmanager',
                 nodeExporter: 'openshift/prometheus-node-exporter',
               },
               versions+:: {
                 openshiftOauthProxy: 'v1.1.0',
               },
               etcd+:: {
                 ips: [],
                 clientCA: '',
                 clientKey: '',
                 clientCert: '',
                 serverName: '',
               },
             },
           } +
           (import 'rules.jsonnet') +
           (import 'prometheus-operator.jsonnet') +
           (import 'node-exporter.jsonnet') +
           (import 'kube-state-metrics.jsonnet') +
           (import 'grafana.jsonnet') +
           (import 'alertmanager.jsonnet') +
           (import 'prometheus.jsonnet') +
           (import 'cluster-monitoring-operator.jsonnet') +
           (import 'remove_runbook.libsonnet') + {
  _config+:: {
    namespace: 'openshift-monitoring',

    hostNetworkInterfaceSelector: 'device!~"veth.+"',

    kubeletTooManyPods: 250,

    kubeSchedulerSelector: 'job="kube-controllers"',
    kubeControllerManagerSelector: 'job="kube-controllers"',
    namespaceSelector: 'namespace=~"(openshift-.*|kube-.*|default|logging)"',
  },
} + {
  local d = super.grafanaDashboards,
  grafanaDashboards:: {
    [k]: d[k]
    for k in std.objectFields(d)
    if !std.setMember(k, ['nodes.json', 'pods.json', 'statefulset.json'])
  },
} + {
  // This patches the way we calculate memory requests and only takes pending and running Pods into account:
  // https://bugzilla.redhat.com/show_bug.cgi?id=1691893
  prometheusRules+::
    local replaceMemoryRule(rule) = (
      if ('record' in rule) && (rule.record == 'namespace_name:kube_pod_container_resource_requests_memory_bytes:sum') then
        rule {
          expr: |||
            sum by (namespace, label_name) (
              sum(kube_pod_container_resource_requests_memory_bytes{%(kubeStateMetricsSelector)s} * on (endpoint, instance, job, namespace, pod, service) group_left(phase) (kube_pod_status_phase{phase=~"^(Pending|Running)$"} == 1)) by (namespace, pod)
            * on (namespace, pod) group_left(label_name)
              label_replace(kube_pod_labels{%(kubeStateMetricsSelector)s}, "pod_name", "$1", "pod", "(.*)")
            )
          ||| % $._config,
        }
      else
        rule
    );
    utils.mapRuleGroups(replaceMemoryRule),
} + {
  // This patches the way we calculate CPU requests and only takes pending and running Pods into account:
  // https://bugzilla.redhat.com/show_bug.cgi?id=1691893
  prometheusRules+::
    local replaceCPURule(rule) = (
      if ('record' in rule) && (rule.record == 'namespace_name:kube_pod_container_resource_requests_cpu_cores:sum') then
        rule {
          expr: |||
            sum by (namespace, label_name) (
              sum(kube_pod_container_resource_requests_cpu_cores{%(kubeStateMetricsSelector)s} * on (endpoint, instance, job, namespace, pod, service) group_left(phase) (kube_pod_status_phase{phase=~"^(Pending|Running)$"} == 1)) by (namespace, pod)
            * on (namespace, pod) group_left(label_name)
              label_replace(kube_pod_labels{%(kubeStateMetricsSelector)s}, "pod_name", "$1", "pod", "(.*)")
            )
          ||| % $._config,
        }
      else
        rule
    );
    utils.mapRuleGroups(replaceCPURule),
} + {
  // This patches the KubeletTooManyPods alert message
  // https://bugzilla.redhat.com/show_bug.cgi?id=1690951#c6
  prometheusAlerts+::
    local replaceKubeletTooManyPodsMessage(rule) = (
      if ('alert' in rule) && (rule.alert == 'KubeletTooManyPods') then
        rule {
          expr: |||
            kubelet_running_pod_count{%(kubeletSelector)s} > %(kubeletTooManyPods)s * 0.9
          ||| % $._config,
          annotations: {
            message: 'Kubelet {{ $labels.instance }} is running {{ $value }} Pods, close to the limit of %d.' % $._config.kubeletTooManyPods,
          },
        }
      else
        rule
    );
    utils.mapRuleGroups(replaceKubeletTooManyPodsMessage),
} + {
  // This patches the KubePodCrashLooping alert expression to use 5 minute range
  // https://bugzilla.redhat.com/show_bug.cgi?id=1700195
  prometheusAlerts+::
    local replaceKubePodCrashLoopingExpression(rule) = (
      if ('alert' in rule) && (rule.alert == 'KubePodCrashLooping') then
        rule {
          expr: |||
            rate(kube_pod_container_status_restarts_total{%(prefixedNamespaceSelector)s%(kubeStateMetricsSelector)s}[15m]) * 60 * 5 > 0
          ||| % $._config,
          annotations: {
            message: 'Pod {{ $labels.namespace }}/{{ $labels.pod }} ({{ $labels.container }}) is restarting {{ printf "%.2f" $value }} times / 5 minutes.',
          },
        }
      else
        rule
    );
    utils.mapRuleGroups(replaceKubePodCrashLoopingExpression),
};

{ ['prometheus-operator/' + name]: kp.prometheusOperator[name] for name in std.objectFields(kp.prometheusOperator) } +
{ ['node-exporter/' + name]: kp.nodeExporter[name] for name in std.objectFields(kp.nodeExporter) } +
{ ['kube-state-metrics/' + name]: kp.kubeStateMetrics[name] for name in std.objectFields(kp.kubeStateMetrics) } +
{ ['alertmanager/' + name]: kp.alertmanager[name] for name in std.objectFields(kp.alertmanager) } +
{ ['prometheus-k8s/' + name]: kp.prometheus[name] for name in std.objectFields(kp.prometheus) } +
{ ['grafana/' + name]: kp.grafana[name] for name in std.objectFields(kp.grafana) } +
{ ['cluster-monitoring-operator/' + name]: kp.clusterMonitoringOperator[name] for name in std.objectFields(kp.clusterMonitoringOperator) }
