local textfileDir = '/var/node_exporter/textfile';
local textfileVolumeName = 'node-exporter-textfile';
local tlsVolumeName = 'node-exporter-tls';
local wtmpPath = '/var/log/wtmp';
local wtmpVolumeName = 'node-exporter-wtmp';

local nodeExporter = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/node-exporter.libsonnet';

function(params)
  local cfg = params;

  nodeExporter(cfg) {

    // Adding the serving certs annotation causes the serving certs controller
    // to generate a valid and signed serving certificate and put it in the
    // specified secret.
    service+: {
      metadata+: {
        annotations+: {
          'service.beta.openshift.io/serving-cert-secret-name': 'node-exporter-tls',
        },
      },
    },

    // This changes node-exporter to be scraped with validating TLS.
    serviceMonitor+: {
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

    securityContextConstraints: {
      allowHostDirVolumePlugin: true,
      allowHostNetwork: true,
      allowHostPID: true,
      allowHostPorts: true,
      allowPrivilegedContainer: true,
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

    clusterRole+: {
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
    daemonset+: {
      spec+: {
        template+: {
          spec+: {
            initContainers+: [
              {
                name: 'init-textfile',
                command: ['/bin/sh', '-c', '[[ ! -d /node_exporter/collectors/init ]] || find /node_exporter/collectors/init -perm /111 -type f -exec {} \\;'],
                env: [{ name: 'TMPDIR', value: '/tmp' }],
                image: cfg.image,
                resources: {
                  requests: {
                    cpu: '1m',
                    memory: '1Mi',
                  },
                },
                securityContext: {
                  privileged: true,
                  runAsUser: 0,
                },
                terminationMessagePolicy: 'FallbackToLogsOnError',
                volumeMounts+: [
                  {
                    mountPath: textfileDir,
                    name: textfileVolumeName,
                    readOnly: false,
                  },
                  {
                    mountPath: wtmpPath,
                    name: wtmpVolumeName,
                    readOnly: true,
                  },
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
                      volumeMounts: [{
                        mountPath: '/etc/tls/private',
                        name: tlsVolumeName,
                        readOnly: false,
                      }],
                      resources: {
                        requests: {
                          memory: '15Mi',
                          cpu: '1m',
                        },
                      },
                    }
                  else
                    c {
                      // Remove the flag to disable hwmon that is set upstream so we
                      // gather that data (especially for bare metal clusters), and
                      // add flags to collect the node_cpu_info metric + metrics
                      // from the text file.
                      args: [a for a in c.args if a != '--no-collector.hwmon'] + ['--collector.cpu.info', '--collector.textfile.directory=' + textfileDir],
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                      volumeMounts+: [{
                        mountPath: textfileDir,
                        name: textfileVolumeName,
                        readOnly: true,
                      }],
                      workingDir: textfileDir,
                      resources+: {
                        requests+: {
                          cpu: '8m',
                          memory: '32Mi',
                        },
                      },
                    },
                super.containers,
              ),
            volumes+: [
              {
                name: textfileVolumeName,
                emptyDir: {},
              },
              {
                name: tlsVolumeName,
                secret: {
                  secretName: 'node-exporter-tls',
                },
              },
              {
                name: wtmpVolumeName,
                hostPath: {
                  path: wtmpPath,
                  type: 'File',
                },
              },
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
  }
