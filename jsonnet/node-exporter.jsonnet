local k = import 'ksonnet/ksonnet.beta.3/k.libsonnet';
local service = k.core.v1.service;
local daemonset = k.apps.v1beta2.daemonSet;
local container = daemonset.mixin.spec.template.spec.containersType;
local volume = daemonset.mixin.spec.template.spec.volumesType;
local configmap = k.core.v1.configMap;
local containerPort = container.portsType;
local containerVolumeMount = container.volumeMountsType;
local textfileDir = '/var/node_exporter/textfile';
local textfileVolumeName = 'node-exporter-textfile';
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
          endpoints: std.map(
            function(e) e {
              tlsConfig+: {
                caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
                serverName: 'server-name-replaced-at-runtime',
                insecureSkipVerify: false,
              },
            },
            super.endpoints
          ),
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

    clusterRole+:
      {
        rules+: [{
          apiGroups: ['security.openshift.io'],
          resources: ['securitycontextconstraints'],
          resourceNames: ['node-exporter'],
          verbs: ['use'],
        }],
      },

    // This configures the kube-rbac-proxies to use the serving cert
    // configured on the `Service` above and adds the default init text
    // collectors to the process.

    daemonset+:
      {
        spec+: {
          template+: {
            spec+: {
              initContainers+: [
                {
                  name: 'init-textfile',
                  command: ['/bin/sh', '-c', '[[ ! -d /node_exporter/collectors/init ]] || find /node_exporter/collectors/init -perm /111 -type f -exec {} \\;'],
                  env: [{name: "TMPDIR", value: "/tmp"}],
                  image: $._config.imageRepos.nodeExporter + ':' + $._config.versions.nodeExporter,
                  resources: {},
                  securityContext: {
                    runAsUser: 0,
                  },
                  terminationMessagePolicy: 'FallbackToLogsOnError',
                  volumeMounts+: [
                    containerVolumeMount.new(textfileVolumeName, textfileDir),
                  ],
                  workingDir: textfileDir,
                },
              ],
              containers:
                std.map(
                  function(c)
                    if c.name == 'kube-rbac-proxy' then
                      c {
                        args+: [
                          '--tls-cert-file=/etc/tls/private/tls.crt',
                          '--tls-private-key-file=/etc/tls/private/tls.key',
                        ],
                        terminationMessagePolicy: 'FallbackToLogsOnError',
                        volumeMounts: [
                          containerVolumeMount.new(tlsVolumeName, '/etc/tls/private'),
                        ],
                      }
                    else
                      c {
                        args+: [
                          '--no-collector.wifi',
                          '--no-collector.hwmon',
                          '--no-collector.netstat',
                          '--no-collector.sockstat',
                          '--no-collector.entropy',
                          '--no-collector.filefd',
                          '--no-collector.time',
                          '--no-collector.textfile',
                          '--no-collector.conntrack',
                          '--no-collector.bcache',
                          '--no-collector.stat',
                          '--no-collector.pressure',
                          '--no-collector.uname',
                          '--no-collector.arp',
                          '--collector.mountstats',
                          '--collector.cpu.info',
                          '--collector.textfile.directory='+textfileDir
                          ],
                        resources: {},
                        terminationMessagePolicy: 'FallbackToLogsOnError',
                        volumeMounts+: [
                          containerVolumeMount.new(textfileVolumeName, textfileDir, true),
                        ],
                        workingDir: textfileDir,
                      },
                  super.containers,
                ),
              volumes+: [
                volume.fromEmptyDir(textfileVolumeName),
                volume.fromSecret(tlsVolumeName, 'node-exporter-tls'),
              ],
              securityContext: {},
              priorityClassName: 'system-cluster-critical',
              tolerations: [
                { operator: 'Exists' },
              ],
            },
          },
        },
      },
  },
}
