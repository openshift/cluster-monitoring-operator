local addon = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/addons/anti-affinity.libsonnet';

addon {
  values+:: {
    prometheus+: {
      podAntiAffinity: 'soft',
    },
    prometheusAdapter+: {
      podAntiAffinity: 'hard',
    },
  },
}
