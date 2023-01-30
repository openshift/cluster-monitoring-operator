local addon = import 'github.com/jan--f/kube-prometheus/jsonnet/kube-prometheus/addons/anti-affinity.libsonnet';

addon {
  values+:: {
    alertmanager+:: {
      podAntiAffinity: 'hard',
    },
    prometheus+: {
      podAntiAffinity: 'hard',
    },
    prometheusAdapter+: {
      podAntiAffinity: 'hard',
    },
  },
}
