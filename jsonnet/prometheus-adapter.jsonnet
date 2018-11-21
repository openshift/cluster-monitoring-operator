local k = import 'ksonnet/ksonnet.beta.3/k.libsonnet';
local service = k.core.v1.service;
local deployment = k.apps.v1beta2.deployment;
local container = deployment.mixin.spec.template.spec.containersType;
local volume = deployment.mixin.spec.template.spec.volumesType;
local configmap = k.core.v1.configMap;
local containerPort = container.portsType;
local containerVolumeMount = container.volumeMountsType;
local tmpVolumeName = 'volume-directive-shadow';
local tlsVolumeName = 'kube-state-metrics-tls';

{
  prometheusAdapter+:: {
    service+:
      service.mixin.metadata.withAnnotations({
        'service.alpha.openshift.io/serving-cert-secret-name': 'kube-state-metrics-tls',
      }),

    deployment+:
      {
        spec+: {
          template+: {
            spec+: {
              securityContext: {},
              priorityClassName: 'system-cluster-critical',
            },
          },
        },
      },
  },
}
