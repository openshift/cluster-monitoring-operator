local generateServiceMonitor = import '../utils/generate-service-monitors.libsonnet';
local telemetryGen = import '../utils/telemetry-allowlist-and-monitors.libsonnet';
local controlPlane = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/k8s-control-plane.libsonnet';

function(params)
  local cfg = params;

  controlPlane(cfg) + {

    etcdMixin:: (import 'github.com/etcd-io/etcd/contrib/mixin/mixin.libsonnet') + {
      _config+:: cfg.mixin._config,
    },

    // This changes the kubelet's certificates to be validated when
    // scraping.
    serviceMonitorKubelet+: {
      metadata+: {
        labels+: {
          'k8s-app': 'kubelet',
          'monitoring.openshift.io/collection-profile': 'full',
        },
      },
      spec+: {
        serviceDiscoveryRole: 'EndpointSlice',
        jobLabel: 'k8s-app',
        selector: {
          matchLabels: {
            'k8s-app': 'kubelet',
          },
        },
        attachMetadata: {
          node: true,
        },
        endpoints:
          std.map(
            function(e)
              e {
                tlsConfig+: {
                  caFile: '/etc/prometheus/configmaps/kubelet-serving-ca-bundle/ca-bundle.crt',
                },
                // Increase the scrape timeout to match the scrape interval
                // because the kubelet metric endpoints might take more than the default
                // 10 seconds to reply.
                scrapeTimeout: '30s',
              }
              +
              if 'path' in e && e.path == '/metrics/cadvisor' then
                // Drop cAdvisor metrics with excessive cardinality.
                {
                  // cAdvisor doesn't scrape metrics at scrape time but rather
                  // exposes timestamps. We want to honor these timestamps, i.e.
                  // ingest them instead of using the normal prometheus scrape
                  // timestamps
                  honorTimestamps: true,
                  // Since prometheus 2.48.0 prometheus can apply the low
                  // latency staleness handling to metrics with exposed
                  // timestamps. This setting was added in prometheus-operator
                  // 0.70.0 to enable this behavior on a per-scrape job basis.
                  trackTimestampsStaleness: true,
                  metricRelabelings+: [
                    {
                      sourceLabels: ['__name__'],
                      action: 'drop',
                      regex: 'container_memory_failures_total',
                    },
                    // stash 'container_fs_usage_bytes' because we don't want to include it in the drop set
                    {
                      sourceLabels: ['__name__'],
                      regex: 'container_fs_usage_bytes',
                      targetLabel: '__tmp_keep_metric',
                      replacement: 'true',
                    },
                    {
                      // these metrics are available at the slice level
                      sourceLabels: ['__tmp_keep_metric', '__name__', 'container'],
                      action: 'drop',
                      regex: ';(container_fs_.*);.+',
                    },
                    // drop the temporarily stashed metrics
                    {
                      action: 'labeldrop',
                      regex: '__tmp_keep_metric',
                    },
                  ],
                }
              else
                {}
            ,
            [e for e in super.endpoints if std.get(e, 'path', '') != '/metrics/slis'],
          ) +
          // Collect metrics from CRI-O.
          [{
            interval: '30s',
            port: 'https-metrics',
            scheme: 'https',
            tlsConfig+: {
              caFile: '/etc/prometheus/configmaps/kubelet-serving-ca-bundle/ca-bundle.crt',
            },
            relabelings: [
              {
                sourceLabels: ['__meta_kubernetes_node_label_kubernetes_io_os'],
                action: 'keep',
                regex: '(linux|)',
              },
              {
                sourceLabels: ['__address__'],
                action: 'replace',
                targetLabel: '__address__',
                regex: '(.+)(?::\\d+)',
                replacement: '$1:9637',
              },
              {
                sourceLabels: ['endpoint'],
                action: 'replace',
                targetLabel: 'endpoint',
                replacement: 'crio',
              },
              {
                action: 'replace',
                targetLabel: 'job',
                replacement: 'crio',
              },
            ],
          }],
      },
    },

    minimalServiceMonitorKubelet: generateServiceMonitor.minimal(
      self.serviceMonitorKubelet, std.join('|',
                                           [
                                             'apiserver_audit_event_total',
                                             'container_cpu_cfs_periods_total',
                                             'container_cpu_cfs_throttled_periods_total',
                                             'container_cpu_usage_seconds_total',
                                             'container_fs_reads_bytes_total',
                                             'container_fs_reads_total',
                                             'container_fs_usage_bytes',
                                             'container_fs_writes_bytes_total',
                                             'container_fs_writes_total',
                                             'container_memory_cache',
                                             'container_memory_rss',
                                             'container_memory_swap',
                                             'container_memory_usage_bytes',
                                             'container_memory_working_set_bytes',
                                             'container_network_receive_bytes_total',
                                             'container_network_receive_packets_dropped_total',
                                             'container_network_receive_packets_total',
                                             'container_network_transmit_bytes_total',
                                             'container_network_transmit_packets_dropped_total',
                                             'container_network_transmit_packets_total',
                                             'container_spec_cpu_shares',
                                             'kubelet_certificate_manager_client_expiration_renew_errors',
                                             'kubelet_containers_per_pod_count_sum',
                                             'kubelet_node_name',
                                             'kubelet_pleg_relist_duration_seconds_bucket',
                                             'kubelet_pod_worker_duration_seconds_bucket',
                                             'kubelet_server_expiration_renew_errors',
                                             'kubelet_volume_stats_available_bytes',
                                             'kubelet_volume_stats_capacity_bytes',
                                             'kubelet_volume_stats_inodes',
                                             'kubelet_volume_stats_inodes_free',
                                             'kubelet_volume_stats_inodes_used',
                                             'kubelet_volume_stats_used_bytes',
                                             'machine_cpu_cores',
                                             'machine_memory_bytes',
                                             'process_start_time_seconds',
                                             'rest_client_requests_total',
                                             'storage_operation_duration_seconds_count',
                                           ])
    ),

    telemetryServiceMonitorKubelet: generateServiceMonitor.telemetry(
      self.serviceMonitorKubelet, std.join(
        '|',
        telemetryGen.monitorKeysToMetricsMap[cfg.namespace + '/' + 'kubelet-telemetry']
      )
    ),


    // This avoids creating service monitors which are already managed by the respective operators.
    serviceMonitorApiserver:: {},
    serviceMonitorKubeScheduler:: {},
    serviceMonitorKubeControllerManager:: {},
    serviceMonitorCoreDNS:: {},

  }
