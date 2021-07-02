local addon = import 'github.com/PhilipGough/kube-prometheus/jsonnet/kube-prometheus/addons/anti-affinity.libsonnet';

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
