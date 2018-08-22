{
  _config+:: {
    grafanaDashboardIDs+:: {
      'openshift-dashboard.json': 'abcd',
    },
  },
  grafanaDashboards+:: {
    "openshift-dashboard.json":
      local grafana = import 'grafonnet/grafana.libsonnet';
      local dashboard = grafana.dashboard;
      local graphPanel = grafana.graphPanel;
      local prometheus = grafana.prometheus;
      local row = grafana.row;
      local template = grafana.template;
      
      grafana.dashboard.new(
          'Openshift metrics',
          refresh='2m',
          time_from='now-1h',
          uid=($._config.grafanaDashboardIDs['openshift-dashboard.json']),
          tags=['openshift']
      )
      .addTemplate(
          {
                current: {
                  text: 'Prometheus',
                  value: 'Prometheus',
                },
                hide: 0,
                label: null,
                name: 'datasource',
                options: [],
                query: 'prometheus',
                refresh: 1,
                regex: '',
                type: 'datasource',
          },
      )
    .addTemplate(
        template.new(
          'namespace',
          '$datasource',
          'label_values(kube_pod_info, namespace)',
          label='Namespace',
          refresh='time',
        )
      )
      .addTemplate(
        template.new(
          'pod',
          '$datasource',
          'label_values(kube_pod_info{namespace=~"$namespace"}, pod)',
          label='Pod',
          refresh='time',
        )
      )
      .addTemplate(
        template.new(
          'container',
          '$datasource',
          'label_values(kube_pod_container_info{namespace="$namespace", pod="$pod"}, container)',
          label='Container',
          refresh='time',
          includeAll=true,
        )
      )
      .addRow(
          row.new(
              'API Server',
              height='125px',
          )
          .addPanel(
              graphPanel.new(
                'Number of mutating API requests being made to the control plane',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'sort_desc(sum without (instance,type,client,contentType) (irate(apiserver_request_count{verb!~"GET|LIST|WATCH"}[2m]))) > 0' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'Number of non-mutating API requests being made to the control plane',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'sort_desc(sum without (instance,type,client,contentType) (irate(apiserver_request_count{verb=~\"GET|LIST|WATCH\"}[2m]))) > 0' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'Endpoint queue latency',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'endpoint_queue_latency' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'Number of non-mutating API requests being made to the control plane',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'sort_desc(sum without (instance,type,client,contentType) (irate(apiserver_request_count{verb=~\"GET|LIST|WATCH\"}[2m]))) > 0' % $._config,
                  )
              )
          )
      )
      .addRow(
          row.new(
              'Openshift SDN',
              height='125px',
          )
          .addPanel(
              graphPanel.new(
                'openshift_sdn_pod_setup_latency_sum',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'openshift_sdn_pod_setup_latency_sum' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'openshift_sdn_pod_teardown_latency',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'openshift_sdn_pod_teardown_latency' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'openshift_sdn_pod_ips',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'openshift_sdn_pod_ips' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'openshift_sdn_pod_ips',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'openshift_sdn_pod_ips' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'garbage_collector_monitoring_route:openshift:io_v1_rate_limiter_use',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'garbage_collector_monitoring_route:openshift:io_v1_rate_limiter_use' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'openshift_sdn_arp_cache_entries',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'openshift_sdn_arp_cache_entries' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'openshift_sdn_arp_cache_entries',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'openshift_sdn_arp_cache_entries' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'Top 10 pods doing the most receive network traffic',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'topk(10, (sum by (pod_name) (irate(container_network_receive_bytes_total[5m]))))' % $._config,
                  )
              )
          )
      )
      .addRow(
          row.new(
              'Openshift Volumes',
              height='125px',
          )
          .addPanel(
              graphPanel.new(
                'Volumes queue latency',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'volumes_queue_latency' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'Count of cloudprovider AWS API request duration in seconds',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'cloudprovider_aws_api_request_duration_seconds_count' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'Sum of storage operation duration in seconds',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'storage_operation_duration_seconds_sum' % $._config,
                  )
              )
          )
      )
      .addRow(
          row.new(
              'Openshift Builds',
              height='125px',
          )
          .addPanel(
              graphPanel.new(
                'Openshift build total',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'openshift_build_total' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'number of builds that have been running for more than 10 minutes (600 seconds)',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'count(openshift_build_active_time_seconds{phase=\"Running\"} < time() - 600)' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'Number of build that have been waiting at least 10 minutes (600 seconds) to start',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'count(openshift_build_active_time_seconds{phase=\"Pending\"} < time() - 600)' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'Returns the number of failed builds, regardless of the failure reason',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'sum(openshift_build_total{phase=\"Failed\"})' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'Returns the number of failed builds because of problems retrieving source from the associated Git repository',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'openshift_build_total{phase=\"Failed\",reason=\"fetchsourcefailed\"}' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'Returns the number of successfully completed builds',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'sum(openshift_build_total{phase=\"Complete\"})' % $._config,
                  )
              )
          )
          .addPanel(
              graphPanel.new(
                'Returns the failed builds totals, per failure reason, from 5 minutes ago',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'openshift_build_total{phase=\"Failed\"} offset 5m' % $._config,
                  )
              )
          )
      )
      .addRow(
          row.new(
              'Changes in your cluster',
              height='125px',
          )
          .addPanel(
              graphPanel.new(
                'The number of containers that start or restart over the last ten minutes',
                datasource='$datasource',
                min=0,
                format='bytes',
                legend_rightSide=true,
                legend_alignAsTable=true,
                legend_current=true,
                legend_avg=true,
              )
              .addTarget(
                  prometheus.target(
                      'sum(changes(container_start_time_seconds[10m]))' % $._config,
                  )
              )
          )
      )
  }
}
