local kp = (import 'kube-prometheus/kube-prometheus.libsonnet') +
           (import 'Openshiftmetrics.jsonnet') +
           (import 'kube-prometheus/kube-prometheus-static-etcd.libsonnet') +
           {
             _config+:: {
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
           (import 'cluster-monitoring-operator.jsonnet') + {
  _config+:: {
    namespace: 'openshift-monitoring',

    kubeSchedulerSelector: 'job="kube-controllers"',
    kubeControllerManagerSelector: 'job="kube-controllers"',
  },
};

{ ['prometheus-operator/' + name]: kp.prometheusOperator[name] for name in std.objectFields(kp.prometheusOperator) } +
{ ['node-exporter/' + name]: kp.nodeExporter[name] for name in std.objectFields(kp.nodeExporter) } +
{ ['kube-state-metrics/' + name]: kp.kubeStateMetrics[name] for name in std.objectFields(kp.kubeStateMetrics) } +
{ ['alertmanager/' + name]: kp.alertmanager[name] for name in std.objectFields(kp.alertmanager) } +
{ ['prometheus-k8s/' + name]: kp.prometheus[name] for name in std.objectFields(kp.prometheus) } +
{ ['grafana/' + name]: kp.grafana[name] for name in std.objectFields(kp.grafana) } +
{ ['cluster-monitoring-operator/' + name]: kp.clusterMonitoringOperator[name] for name in std.objectFields(kp.clusterMonitoringOperator) }
