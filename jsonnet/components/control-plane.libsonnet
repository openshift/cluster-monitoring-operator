local controlPlane = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/k8s-control-plane.libsonnet';

function(params)
  local cfg = params;

  controlPlane(cfg) + {

    etcdMixin:: (import 'github.com/etcd-io/etcd/contrib/mixin/mixin.libsonnet') + {
      _config+:: cfg.mixin._config,
    },

    serviceMonitorEtcd: {
      apiVersion: 'monitoring.coreos.com/v1',
      kind: 'ServiceMonitor',
      metadata: {
        name: 'etcd',
        namespace: cfg.namespace,
        labels: {
          'app.kubernetes.io/name': 'etcd',
          'k8s-app': 'etcd',
          'monitoring.openshift.io/scrape-profile': 'full',
        },
      },
      spec: {
        jobLabel: 'k8s-app',
        endpoints: [
          {
            port: 'etcd-metrics',
            interval: '30s',
            scheme: 'https',
            // Prometheus Operator (and Prometheus) allow us to specify a tlsConfig. This is required as most likely your etcd metrics end points is secure.
            tlsConfig: {
              caFile: '/etc/prometheus/secrets/kube-etcd-client-certs/etcd-client-ca.crt',
              keyFile: '/etc/prometheus/secrets/kube-etcd-client-certs/etcd-client.key',
              certFile: '/etc/prometheus/secrets/kube-etcd-client-certs/etcd-client.crt',
            },
          },
        ],
        selector: {
          matchLabels: {
            'k8s-app': 'etcd',
          },
        },
        namespaceSelector: {
          matchNames: ['openshift-etcd'],
        },
      },
    },

    operationalServiceMonitorEtcd: self.serviceMonitorEtcd {
      metadata+: {
        name: super.name + '-operational',
        labels+: {
          'monitoring.openshift.io/scrape-profile': 'operational',
        },
      },
      spec+: {
        endpoints: std.map(
          function(e) e {
            metricRelabelings+: [
              {
                sourceLabels: ['__name__'],
                action: 'keep',
                regex: '(' + std.join('|',
                                      [
                                        'etcd_disk_backend_commit_duration_seconds_bucket',
                                        'etcd_disk_wal_fsync_duration_seconds_bucket',
                                        'etcd_mvcc_db_total_size_in_bytes',
                                        'etcd_mvcc_db_total_size_in_use_in_bytes',
                                        'etcd_network_peer_round_trip_time_seconds_bucket',
                                        'etcd_network_peer_sent_failures_total',
                                        'etcd_server_has_leader',
                                        'etcd_server_is_leader',
                                        'etcd_server_proposals_failed_total',
                                        'etcd_server_quota_backend_bytes',
                                        'grpc_server_handled_total',
                                        'grpc_server_handling_seconds_bucket',
                                        'grpc_server_started_total',
                                      ]) + ')',
              },
            ],
          },
          super.endpoints
        ),
      },
    },

    uponlyServiceMonitorEtcd: self.serviceMonitorEtcd {
      metadata+: {
        name: super.name + '-uponly',
        labels+: {
          'monitoring.openshift.io/scrape-profile': 'uponly',
        },
      },
      spec+: {
        endpoints: std.map(
          function(e) e {
            metricRelabelings+: [
              {
                sourceLabels: ['__name__'],
                action: 'drop',
                regex: '.+',
              },
            ],
          },
          super.endpoints
        ),
      },
    },

    // This changes the kubelet's certificates to be validated when
    // scraping.
    serviceMonitorKubelet+: {
      metadata+: {
        labels+: {
          'k8s-app': 'kubelet',
          'monitoring.openshift.io/scrape-profile': 'full',
        },
      },
      spec+: {
        jobLabel: 'k8s-app',
        selector: {
          matchLabels: {
            'k8s-app': 'kubelet',
          },
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
            super.endpoints,
          ) +
          // Collect metrics from CRI-O.
          [{
            interval: '30s',
            port: 'https-metrics',
            relabelings: [
              {
                sourceLabels: ['__address__'],
                action: 'replace',
                targetLabel: '__address__',
                regex: '(.+)(?::\\d+)',
                replacement: '$1:9537',
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

    operationalServiceMonitorKubelet: self.serviceMonitorKubelet {
      metadata+: {
        name: super.name + '-operational',
        labels+: {
          'monitoring.openshift.io/scrape-profile': 'operational',
        },
      },
      spec+: {
        endpoints: std.map(
          function(e) e +
                      if !std.objectHas(e, 'metricRelabelings') && e.port == 'https-metrics' then {
                        metricRelabelings+: [
                          {
                            sourceLabels: ['__name__'],
                            action: 'drop',
                            regex: '.+',
                          },
                        ],
                      } else {} +
                             if std.objectHas(e, 'metricRelabelings') && e.port == 'https-metrics' then {
                               metricRelabelings+: [
                                 {
                                   sourceLabels: ['__name__'],
                                   action: 'keep',
                                   regex: '(' + std.join('|',
                                                         [
                                                           'apiserver_audit_event_total',
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
                                                         ]) + ')',
                                 },
                               ],
                             } else {} +
                                    if std.objectHas(e, 'path') && e.path == '/metrics/cadvisor' then {
                                      metricRelabelings+: [
                                        {
                                          sourceLabels: ['__name__'],
                                          action: 'keep',
                                          regex: '(' + std.join('|',
                                                                [
                                                                  'container_cpu_usage_seconds_total',
                                                                  'container_fs_usage_bytes',
                                                                  'container_memory_cache',
                                                                  'container_memory_rss',
                                                                  'container_memory_swap',
                                                                  'container_memory_usage_bytes',
                                                                  'container_memory_working_set_bytes',
                                                                  'container_spec_cpu_shares',
                                                                  'machine_cpu_cores',
                                                                  'machine_memory_bytesmachine_cpu_cores',
                                                                  'machine_memory_bytes',
                                                                ]) + ')',
                                        },
                                      ],
                                    } else {} +
                                           if std.objectHas(e, 'path') && e.path == '/metrics/probes' then {
                                             metricRelabelings+: [
                                               {
                                                 sourceLabels: ['__name__'],
                                                 action: 'drop',
                                                 regex: '.+',
                                               },
                                             ],
                                           } else {},
          super.endpoints
        ),
      },
    },

    uponlyServiceMonitorKubelet: self.serviceMonitorKubelet {
      metadata+: {
        name: super.name + '-uponly',
        labels+: {
          'monitoring.openshift.io/scrape-profile': 'uponly',
        },
      },
      spec+: {
        endpoints: std.map(
          function(e) e {
            metricRelabelings+: [
              {
                sourceLabels: ['__name__'],
                action: 'drop',
                regex: '.+',
              },
            ],
          },
          super.endpoints
        ),
      },
    },


    // This adds a kubelet ServiceMonitor for special use with
    // prometheus-adapter if enabled by the configuration of the cluster monitoring operator.
    serviceMonitorKubeletResourceMetrics: self.serviceMonitorKubelet {
      metadata+: {
        name: 'kubelet-resource-metrics',
      },
      spec+: {
        endpoints:
          std.filterMap(
            function(e)
              'path' in e && e.path == '/metrics/cadvisor'
            ,
            function(e)
              e {
                path: '/metrics/resource',
                honorTimestamps: true,
                metricRelabelings: [
                  // Keep only container_cpu_usage_seconds_total and container_memory_working_set_bytes metrics.
                  // This is all that the Prometheus adapter needs. Node metrics are provided by node_exporter (Linux) or Windows exporter.
                  // scrape_errors will be useful for troubleshooting.
                  {
                    sourceLabels: ['__name__'],
                    action: 'keep',
                    regex: 'container_cpu_usage_seconds_total|container_memory_working_set_bytes|scrape_error',
                  },
                  // To avoid clashes with the cAdvisor metrics, the resource metrics are prefixed with a distinct identifier.
                  {
                    sourceLabels: ['__name__'],
                    targetLabel: '__name__',
                    replacement: std.format('%s$1', cfg.prometheusAdapterMetricPrefix),
                    action: 'replace',
                  },
                ],
              }
            ,
            super.endpoints,
          ),
      },
    },

    // This avoids creating service monitors which are already managed by the respective operators.
    serviceMonitorApiserver:: {},
    serviceMonitorKubeScheduler:: {},
    serviceMonitorKubeControllerManager:: {},
    serviceMonitorCoreDNS:: {},

  }
