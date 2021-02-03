local kubernetes = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/mixin/kubernetes.libsonnet';
local kubePrometheus = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/mixin/custom.libsonnet';
local additionalRules = import './rules.libsonnet';

local defaults = {
  namespace: error 'must provide namespace',
};

function(params) {
  local m = self,
  config:: defaults + params,

  local etcd = (import 'github.com/etcd-io/etcd/Documentation/etcd-mixin/mixin.libsonnet') + {
    _config+:: m.config.mixin._config,
  },

  local kube = kubernetes(m.config + {name: 'kubernetes-mixin'}),
  local kubeProm = kubePrometheus(m.config + {name: 'kube-prometheus'}),

  grafanaDashboards:: kube.mixin.grafanaDashboards + etcd.grafanaDashboards,

  kubernetesPrometheusRule: kube.prometheusRule,

  kubePrometheusPrometheusRule: kubeProm.prometheusRule,

  additionalPrometheusRule: {
    apiVersion: 'monitoring.coreos.com/v1',
    kind: 'PrometheusRule',
    metadata: {
      labels: m.config.commonLabels + m.config.mixin.ruleLabels,
      name: 'etcd-rules',
      namespace: m.config.namespace,
    },
    spec: additionalRules.prometheusRules,
  },

  etcdPrometheusRule: {
    apiVersion: 'monitoring.coreos.com/v1',
    kind: 'PrometheusRule',
    metadata: {
      labels: m.config.commonLabels + m.config.mixin.ruleLabels,
      name: 'etcd-rules',
      namespace: m.config.namespace,
    },
    spec: {
      local r = if std.objectHasAll(etcd, 'prometheusRules') then etcd.prometheusRules.groups else [],
      local a = if std.objectHasAll(etcd, 'prometheusAlerts') then etcd.prometheusAlerts.groups else [],
      groups: a + r,
    },
  },
}