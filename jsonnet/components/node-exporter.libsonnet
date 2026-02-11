local telemetryGen = import '../utils/telemetry-allowlist-and-monitors.libsonnet';

local textfileDir = '/var/node_exporter/textfile';
local textfileVolumeName = 'node-exporter-textfile';
local tlsVolumeName = 'node-exporter-tls';
local wtmpPath = '/var/log/wtmp';
local wtmpVolumeName = 'node-exporter-wtmp';
local configDir = '/var/node_exporter/accelerators_collector_config';
local configVolumeName = 'node-exporter-accelerators-collector-config';
local acceleratorsConfigFileName = 'config.yaml';
local acceleratorsConfigMapName = 'node-exporter-accelerators-collector-config';
local acceleratorsConfigData = [
  {
    vendorName: 'NVIDIA',
    vendorID: '0x10de',
    models: [
      { pciID: '0x20f5', modelName: 'NVIDIA A800 PCIe 80GB' },
      { pciID: '0x20f6', modelName: 'NVIDIA A800 40GB PCIe active cooled' },
      { pciID: '0x20fd', modelName: 'NVIDIA AX800' },
      { pciID: '0x20f1', modelName: 'NVIDIA A100 PCIe 40GB' },
      { pciID: '0x20b5', modelName: 'NVIDIA A100 PCIe 80GB' },
      { pciID: '0x2235', modelName: 'NVIDIA A40' },
      { pciID: '0x20b7', modelName: 'NVIDIA A30' },
      { pciID: '0x2236', modelName: 'NVIDIA A10' },
      { pciID: '0x25b6', modelName: 'NVIDIA A16' },
      { pciID: '0x2322', modelName: 'H800 NVL' },
      { pciID: '0x2321', modelName: 'NVIDIA H100 NVL' },
      { pciID: '0x2331', modelName: 'NVIDIA H100 PCIe 80GB' },
      { pciID: '0x26b5', modelName: 'NVIDIA L40' },
      { pciID: '0x26b9', modelName: 'NVIDIA L40S' },
      { pciID: '0x26bA', modelName: 'NVIDIA L20 liquid cooled' },
      { pciID: '0x27b8', modelName: 'NVIDIA L4' },
      { pciID: '0x27b6', modelName: 'NVIDIA L2' },
      { pciID: '0x26b1', modelName: 'NVIDIA RTX 6000 Ada' },
      { pciID: '0x26b3', modelName: 'NVIDIA RTX 5880 Ada' },
      { pciID: '0x2231', modelName: 'NVIDIA RTX 5000 Ada' },
      { pciID: '0x2230', modelName: 'NVIDIA RTX A6000' },
      { pciID: '0x2233', modelName: 'NVIDIA RTX A5500' },
      { pciID: '0x1e30', modelName: 'NVIDIA RTX 8000 passive' },
      { pciID: '0x2531', modelName: 'NVIDIA RTX A2000' },
      { pciID: '0x20b0', modelName: 'NVIDIA A100 SXM4 40GB' },
      { pciID: '0x233a', modelName: 'NVIDIA H800 NVL' },
      { pciID: '0x233b', modelName: 'NVIDIA H200 NVL' },
      { pciID: '0x20b2', modelName: 'NVIDIA A100 SXM4 80GB' },
      { pciID: '0x20b3', modelName: 'NVIDIA A100 SXM 64GB' },
      { pciID: '0x20bd', modelName: 'NVIDIA A800 SXM4 40GB' },
      { pciID: '0x20f3', modelName: 'NVIDIA A800 SXM4 80GB' },
      { pciID: '0x25b0', modelName: 'NVIDIA RTX A1000' },
      { pciID: '0x2bb5', modelName: 'Blackwell RTX PRO 6000' },
      { pciID: '0x2941', modelName: 'Blackwell GB100' },
    ],
  },
  {
    vendorName: 'AMD',
    vendorID: '0x1002',
    models: [
      { pciID: '0x740f', modelName: 'AMD MI210' },
      { pciID: '0x740c', modelName: 'AMD MI250' },
      { pciID: '0x7408', modelName: 'AMD MI250X' },
      { pciID: '0x74a0', modelName: 'AMD MI300' },
      { pciID: '0x74a1', modelName: 'AMD MI300X' },
      { pciID: '0x74a5', modelName: 'AMD MI325X' },
      { pciID: '0x7aa2', modelName: 'AMD MI308X' },
      { pciID: '0x74b5', modelName: 'AMD MI300X VF' },
      { pciID: '0x7410', modelName: 'AMD MI210 VF' },
    ],
  },
  {
    vendorName: 'GAUDI',
    vendorID: '0x1da3',
    models: [
      { pciID: '0x1000', modelName: 'Gaudi 1' },
      { pciID: '0x1020', modelName: 'Gaudi 2' },
    ],
  },
  {
    vendorName: 'Intel',
    vendorID: '0x8086',
    models: [
      { pciID: '0x0bd5', modelName: 'Intel Data Center GPU Max 1550' },
      { pciID: '0x0bda', modelName: 'Intel Data Center GPU Max 1100' },
      { pciID: '0x56c0', modelName: 'Intel Data Center GPU Flex 170' },
      { pciID: '0x56c1', modelName: 'Intel Data Center GPU Flex 140' },
      { pciID: '0x1452', modelName: 'Intel IPU Data Path' },
    ],
  },
  {
    vendorName: 'Qualcomm',
    vendorID: '0x17cb',
    models: [
      { pciID: '0xa100', modelName: 'Qualcomm AI 100' },
      { pciID: '0xa080', modelName: 'Qualcomm AI 80' },
    ],
  },
  {
    vendorName: 'Marvell',
    vendorID: '0x177d',
    models: [
      { pciID: '0xb900', modelName: 'Marvell OCTEON 10 CN10XXX' },
    ],
  },
  {
    vendorName: 'Mellanox',
    vendorID: '0x15b3',
    models: [
      { pciID: '0xa2dc', modelName: 'BlueField-3 integrated ConnectX-7' },
    ],
  },

];

local nodeExporter = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/node-exporter.libsonnet';
local generateSecret = import '../utils/generate-secret.libsonnet';
local generateServiceMonitor = import '../utils/generate-service-monitors.libsonnet';
local withDescription = (import '../utils/add-annotations.libsonnet').withDescription;

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
        } + withDescription('Expose the `/metrics` endpoint on port %d. This port is for internal use, and no other usage is guaranteed.' % $.service.spec.ports[0].port),
      },
    },

    // This changes node-exporter to be scraped with validating TLS.
    serviceMonitor+: {
      metadata+: {
        labels+: {
          'monitoring.openshift.io/collection-profile': 'full',
        },
      },
      spec+: {
        serviceDiscoveryRole: 'EndpointSlice',
        endpoints: [
          endpoint {
            local metricRelabelingsOld = if std.objectHas(endpoint, 'metricRelabelings') then endpoint.metricRelabelings else [],
            metricRelabelings:
              metricRelabelingsOld +
              [
                {
                  // Drop other metrics from mountstats collector than these 3 metrics:
                  // 1. node_mountstats_nfs_read_bytes_total
                  // 2. node_mountstats_nfs_write_bytes_total
                  // 3. node_mountstats_nfs_operations_requests_total
                  sourceLabels: ['__name__'],
                  regex+: '(' + std.join('|', [
                    'node_mountstats_nfs_read_bytes_total',
                    'node_mountstats_nfs_write_bytes_total',
                    'node_mountstats_nfs_operations_requests_total',
                  ]) + ')',
                  action: 'replace',
                  targetLabel: '__tmp_keep',
                  replacement: 'true',
                },
                {
                  action: 'drop',
                  sourceLabels: ['__name__', '__tmp_keep'],
                  regex: 'node_mountstats_nfs_.+;',
                },
                {
                  action: 'labeldrop',
                  regex: '__tmp_keep',
                },
              ],
          }
          for endpoint in super.endpoints
        ],
      },
    },

    minimalServiceMonitor: generateServiceMonitor.minimal(
      super.serviceMonitor, std.join('|',
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

    telemetryServiceMonitor: generateServiceMonitor.telemetry(
      super.serviceMonitor, std.join(
        '|',
        telemetryGen.monitorKeysToMetricsMap[cfg.namespace + '/' + 'node-exporter-telemetry']
      )
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
      seccompProfiles: ['runtime/default'],
      users: [],
    },

    clusterRole+: {
      rules+: [
        {
          apiGroups: ['security.openshift.io'],
          resources: ['securitycontextconstraints'],
          resourceNames: ['node-exporter'],
          verbs: ['use'],
        },
      ],
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
            annotations+: {
              'openshift.io/required-scc': 'node-exporter',
              'cluster-autoscaler.kubernetes.io/enable-ds-eviction': 'false',
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
                      // Disable btrfs collector as btrfs is not included in RHEL kernels
                      args: [a for a in c.args if (a != '--no-collector.hwmon' && a != '--no-collector.btrfs')] +
                            [
                              '--collector.cpu.info',
                              '--collector.textfile.directory=' + textfileDir,
                              '--no-collector.btrfs',
                            ],
                      command: [
                        '/bin/sh',
                        '-c',
                        |||
                          export GOMAXPROCS=4
                          # We don't take CPU affinity into account as the container doesn't have integer CPU requests.
                          # In case of error, fallback to the default value.
                          NUM_CPUS=$(grep -c '^processor' "/proc/cpuinfo" 2>/dev/null || echo "0")
                          if [ "$NUM_CPUS" -lt "$GOMAXPROCS" ]; then
                            export GOMAXPROCS="$NUM_CPUS"
                          fi
                          echo "ts=$(date --iso-8601=seconds) num_cpus=$NUM_CPUS gomaxprocs=$GOMAXPROCS"
                          exec /bin/node_exporter "$0" "$@"
                        |||,
                      ],
                      volumeMounts+: [
                        {
                          mountPath: textfileDir,
                          name: textfileVolumeName,
                          readOnly: true,
                        },
                        {
                          mountPath: configDir,
                          name: configVolumeName,
                          readOnly: true,
                        },
                      ],
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
                      env: [
                        {
                          // This is required for the systemd collector to connect to the host's dbus socket.
                          name: 'DBUS_SYSTEM_BUS_ADDRESS',
                          value: 'unix:path=/host/root/var/run/dbus/system_bus_socket',
                        },
                      ],
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
              {
                name: configVolumeName,
                configMap: {
                  name: acceleratorsConfigMapName,
                  items: [
                    {
                      key: acceleratorsConfigFileName,
                      path: acceleratorsConfigFileName,
                    },
                  ],
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

    kubeRbacProxySecret: generateSecret.staticAuthSecret(cfg.namespace, cfg.commonLabels, 'node-exporter-kube-rbac-proxy-config'),

    prometheusRule+: {
      spec+: {
        groups+: [
          {
            name: 'telemetry',
            rules: [
              {
                record: 'vendor_model:node_accelerator_cards:sum',
                expr: 'sum by(vendor,model) (node_accelerator_card_info)',
              },
              // recording the average value allows us to understand which
              // optional collectors are installed across the fleet (e.g.
              // "count by(collector) (group by(_id, collector)
              // (collector:node_scrape_collector_success:avg)") and get a
              // sense of how well they perform.
              {
                record: 'collector:node_scrape_collector_success:avg',
                expr: 'avg by(collector) (node_scrape_collector_success)',
              },
            ],
          },
        ],
      },
    },

    acceleratorsCollectorConfigmap: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: {
        name: acceleratorsConfigMapName,
        namespace: cfg.namespace,
      },
      data: {
        [acceleratorsConfigFileName]: std.manifestYamlDoc(acceleratorsConfigData),
      },
    },
  }
