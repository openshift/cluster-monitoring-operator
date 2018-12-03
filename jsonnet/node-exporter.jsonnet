local k = import 'ksonnet/ksonnet.beta.3/k.libsonnet';
local service = k.core.v1.service;
local daemonset = k.apps.v1beta2.daemonSet;
local container = daemonset.mixin.spec.template.spec.containersType;
local volume = daemonset.mixin.spec.template.spec.volumesType;
local configmap = k.core.v1.configMap;
local containerPort = container.portsType;
local containerVolumeMount = container.volumeMountsType;
local tlsVolumeName = 'node-exporter-tls';

{
  nodeExporter+:: {

    // Adding the serving certs annotation causes the serving certs controller
    // to generate a valid and signed serving certificate and put it in the
    // specified secret.

    service+:
      service.mixin.metadata.withAnnotations({
        'service.alpha.openshift.io/serving-cert-secret-name': 'node-exporter-tls',
      }),

    // This changes node-exporter to be scraped with validating TLS.

    serviceMonitor+:
      {
        spec+: {
          endpoints: [
            {
              bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
              interval: '30s',
              port: 'https',
              scheme: 'https',
              tlsConfig: {
                caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                serverName: 'server-name-replaced-at-runtime',
              },
            },
          ],
        },
      },
    securityContextConstraints:
      {
        allowHostDirVolumePlugin: true,
        allowHostNetwork: true,
        allowHostPID: true,
        allowHostPorts: true,
        apiVersion: 'security.openshift.io/v1',
        kind: 'SecurityContextConstraints',
        metadata: {
          annotations: {
            'kubernetes.io/description': 'node-exporter scc is used for the Prometheus node exporter',
          },
          name: 'node-exporter',
        },
        readOnlyRootFilesystem: false,
        runAsUser: {
          type: 'RunAsAny',
        },
        seLinuxContext: {
          type: 'RunAsAny',
        },
        users: [],
      },

    // This configures the kube-rbac-proxies to use the serving cert
    // configured on the `Service` above.

    daemonset+:
      {
        spec+: {
          template+: {
            spec+: {
              containers:
                std.map(
                  function(c)
                    if c.name == 'kube-rbac-proxy' then
                      c {
                        args+: [
                          '--tls-cert-file=/etc/tls/private/tls.crt',
                          '--tls-private-key-file=/etc/tls/private/tls.key',
                        ],
                        volumeMounts: [
                          containerVolumeMount.new(tlsVolumeName, '/etc/tls/private'),
                        ],
                      }
                    else
                      c {
                        args+: ['--no-collector.wifi'],
                        resources: {},
                      },
                  super.containers,
                ),
              volumes+: [volume.fromSecret(tlsVolumeName, 'node-exporter-tls')],
              securityContext: {},
              priorityClassName: 'system-cluster-critical',
            },
          },
        },
      },
  },
}
