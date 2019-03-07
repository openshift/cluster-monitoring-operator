{
  prometheusRules+:: {
    groups+: [
      {
        name: 'kubernetes.rules',
        rules: [
          {
            expr: 'sum(container_memory_usage_bytes{container_name!="POD",container_name!="",pod_name!=""}) BY (pod_name, namespace)',
            record: 'pod_name:container_memory_usage_bytes:sum',
          },
          {
            expr: 'sum(container_spec_cpu_shares{container_name!="POD",container_name!="",pod_name!=""}) BY (pod_name, namespace)',
            record: 'pod_name:container_spec_cpu_shares:sum',
          },
          {
            expr: 'sum(rate(container_cpu_usage_seconds_total{container_name!="POD",container_name!="",pod_name!=""}[5m])) BY (pod_name, namespace)',
            record: 'pod_name:container_cpu_usage:sum',
          },
          {
            expr: 'sum(container_fs_usage_bytes{container_name!="POD",container_name!="",pod_name!=""}) BY (pod_name, namespace)',
            record: 'pod_name:container_fs_usage_bytes:sum',
          },
          {
            expr: 'sum(container_memory_usage_bytes{container_name!=""}) BY (namespace)',
            record: 'namespace:container_memory_usage_bytes:sum',
          },
          {
            expr: 'sum(container_spec_cpu_shares{container_name!=""}) BY (namespace)',
            record: 'namespace:container_spec_cpu_shares:sum',
          },
          {
            expr: 'sum(rate(container_cpu_usage_seconds_total{container_name!="POD",container_name!=""}[5m])) BY (namespace)',
            record: 'namespace:container_cpu_usage:sum',
          },
          {
            expr: 'sum(container_memory_usage_bytes{container_name!="POD",container_name!="",pod_name!=""}) BY (cluster) / sum(machine_memory_bytes) BY (cluster)',
            record: 'cluster:memory_usage:ratio',
          },
          {
            expr: 'sum(container_spec_cpu_shares{container_name!="POD",container_name!="",pod_name!=""}) / 1000 / sum(machine_cpu_cores)',
            record: 'cluster:container_spec_cpu_shares:ratio',
          },
          {
            expr: 'sum(rate(container_cpu_usage_seconds_total{container_name!="POD",container_name!="",pod_name!=""}[5m])) / sum(machine_cpu_cores)',
            record: 'cluster:container_cpu_usage:ratio',
          },
          {
            expr: 'sum(rate(cluster_monitoring_operator_reconcile_errors_total[15m])) * 100 / sum(rate(cluster_monitoring_operator_reconcile_attempts_total[15m])) > 10',
            alert: 'ClusterMonitoringOperatorErrors',
            'for': '15m',
            annotations: {
              message: 'Cluster Monitoring Operator is experiencing {{ printf "%0.0f" $value }}% errors.',
            },
            labels: {
              severity: 'critical',
            },
          },
        ],
      },
      {
        name: 'openshift-build.rules',
        rules: [
          {
            expr: 'sum(openshift_build_total{job="kubernetes-apiservers",phase="Error"})/(sum(openshift_build_total{job="kubernetes-apiservers",phase=~"Failed|Complete|Error"}))',
            record: 'build_error_rate',
          },
        ],
      },
      {
        name: 'openshift-sre.rules',
        rules: [
          {
            expr: 'sum(rate(apiserver_request_count{job="apiserver"}[10m])) by (code)',
            record: 'code:apiserver_request_count:rate:sum',
          },
          {
            expr:'sum(kube_pod_status_ready{condition="true",namespace="kube-system",pod=~"etcd.*"}) by(condition)',
            record:'kube_pod_status_ready:etcd:sum',
          },
          {
            expr:'sum(kube_pod_status_ready{condition="true",namespace="openshift-image-registry",pod=~"image-registry.*"}) by(condition)',
            record:'kube_pod_status_ready:image_registry:sum',
          },
        ],
      },
    ],
  },
}
