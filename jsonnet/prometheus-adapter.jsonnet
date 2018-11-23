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
    deployment+:
      {
        spec+: {
          template+: {
            spec+: {
              local servingCertsCABundle = 'serving-certs-ca-bundle',
              local servingCertsCABundleFileName = 'service-ca.crt',
              local servingCertsCABundleMountPath = '/etc/%s' % servingCertsCABundle,

              containers:
                std.map(
                  function(c)
                    if c.name == 'prometheus-adapter' then
                      c
                      {
                        args+: [
                          '--prometheus-ca-file=%s/%s' % [servingCertsCABundleMountPath, servingCertsCABundleFileName],
                        ],
                        volumeMouns+: [
                          containerVolumeMount.new(servingCertsCABundle, servingCertsCABundleMountPath),
                        ],
                      }
                    else
                      c,
                  super.containers,
                ),

              volumes+: [
                volume.withName(servingCertsCABundle) + volume.mixin.configMap.withName('prometheus-serving-certs-ca-bundle'),
              ],

              securityContext: {},
              priorityClassName: 'system-cluster-critical',
            },
          },
        },
      },
  },
}
