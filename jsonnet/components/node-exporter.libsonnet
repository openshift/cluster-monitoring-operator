local textfileDir = '/var/node_exporter/textfile';
local textfileVolumeName = 'node-exporter-textfile';
local tlsVolumeName = 'node-exporter-tls';
local wtmpPath = '/var/log/wtmp';
local wtmpVolumeName = 'node-exporter-wtmp';

local nodeExporter = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/node-exporter.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';
local generateServiceMonitor = import '../utils/generate-service-monitors.libsonnet';

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
      metadata+: {
        labels+: {
          'monitoring.openshift.io/collection-profile': 'full',
        },
      },
    },

    minimalServiceMonitor: generateServiceMonitor.minimal(
      self.serviceMonitor, std.join('|',
                                    [
                                      'node_cpu_info',
                                      'node_cpu_seconds_total',
                                      'node_disk_io_time_seconds_total',
                                      'node_disk_io_time_weighted_seconds_total',
                                      'node_disk_read_time_seconds_total',
                                      'node_disk_reads_completed_total',
                                      'node_disk_write_time_seconds_total',
                                      'node_disk_writes_completed_total',
                                      'node_filefd_allocated',
                                      'node_filefd_maximum',
                                      'node_filesystem_avail_bytes',
                                      'node_filesystem_files',
                                      'node_filesystem_files_free',
                                      'node_filesystem_free_bytes',
                                      'node_filesystem_readonly',
                                      'node_filesystem_size_bytes',
                                      'node_load1',
                                      'node_memory_Buffers_bytes',
                                      'node_memory_Cached_bytes',
                                      'node_memory_MemAvailable_bytes',
                                      'node_memory_MemFree_bytes',
                                      'node_memory_MemTotal_bytes',
                                      'node_memory_Slab_bytes',
                                      'node_netstat_TcpExt_TCPSynRetrans',
                                      'node_netstat_Tcp_OutSegs',
                                      'node_netstat_Tcp_RetransSegs',
                                      'node_network_receive_bytes_total',
                                      'node_network_receive_drop_total',
                                      'node_network_receive_errs_total',
                                      'node_network_receive_packets_total',
                                      'node_network_transmit_bytes_total',
                                      'node_network_transmit_drop_total',
                                      'node_network_transmit_errs_total',
                                      'node_network_transmit_packets_total',
                                      'node_network_up',
                                      'node_nf_conntrack_entries',
                                      'node_nf_conntrack_entries_limit',
                                      'node_textfile_scrape_error',
                                      'node_timex_maxerror_seconds',
                                      'node_timex_offset_seconds',
                                      'node_timex_sync_status',
                                      'node_vmstat_pgmajfault',
                                      'process_start_time_seconds',
                                      'virt_platform',
                                    ])
    ),

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
      metadata+: {
        labels+: {
          'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
        },
      },
      spec+: {
        template+: {
          metadata+: {
            labels+: {
              'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
            },
          },
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
                        '--client-ca-file=/etc/tls/client/client-ca.crt',
                        '--config-file=/etc/kube-rbac-policy/config.yaml',
                      ],
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                      volumeMounts: [
                        {
                          mountPath: '/etc/tls/private',
                          name: tlsVolumeName,
                          readOnly: false,
                        },
                        {
                          mountPath: '/etc/tls/client',
                          name: 'metrics-client-ca',
                          readOnly: false,
                        },
                        {
                          mountPath: '/etc/kube-rbac-policy',
                          name: 'node-exporter-kube-rbac-proxy-config',
                          readOnly: true,
                        },
                      ],
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
                      args: [a for a in c.args if (a != '--no-collector.hwmon')] +
                            [
                              '--collector.cpu.info',
                              '--collector.textfile.directory=' + textfileDir,
                            ],
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
                      // node-exporter has issue in rolling out with security context
                      // changes in kube-prometheus hence overidding the changes
                      securityContext: {},
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
              {
                name: 'metrics-client-ca',
                configMap: {
                  name: 'metrics-client-ca',
                },
              },
              {
                name: 'node-exporter-kube-rbac-proxy-config',
                secret: {
                  secretName: 'node-exporter-kube-rbac-proxy-config',
                },
              },
            ],
            priorityClassName: 'system-cluster-critical',
            tolerations: [
              { operator: 'Exists' },
            ],
          },
        },
      },
    },
    kubeRbacProxySecret: generateSecret.staticAuthSecret(cfg.namespace, cfg.commonLabels, 'node-exporter-kube-rbac-proxy-config'),
  }
