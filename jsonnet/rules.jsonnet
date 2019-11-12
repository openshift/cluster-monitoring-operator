{
  prometheusRules+:: {
    groups+: [
      {
        name: 'kubernetes.rules',
        rules: [
          {
            expr: 'sum(container_memory_usage_bytes{container!="POD",container!="",pod!=""}) BY (pod, namespace)',
            record: 'pod:container_memory_usage_bytes:sum',
          },
          {
            expr: 'sum(container_spec_cpu_shares{container!="POD",container!="",pod!=""}) BY (pod, namespace)',
            record: 'pod:container_spec_cpu_shares:sum',
          },
          {
            expr: 'sum(rate(container_cpu_usage_seconds_total{container!="POD",container!="",pod!=""}[5m])) BY (pod, namespace)',
            record: 'pod:container_cpu_usage:sum',
          },
          {
            expr: 'sum(container_fs_usage_bytes{container!="POD",container!="",pod!=""}) BY (pod, namespace)',
            record: 'pod:container_fs_usage_bytes:sum',
          },
          {
            expr: 'sum(container_memory_usage_bytes{container!=""}) BY (namespace)',
            record: 'namespace:container_memory_usage_bytes:sum',
          },
          {
            expr: 'sum(container_spec_cpu_shares{container!=""}) BY (namespace)',
            record: 'namespace:container_spec_cpu_shares:sum',
          },
          {
            expr: 'sum(rate(container_cpu_usage_seconds_total{container!="POD",container!=""}[5m])) BY (namespace)',
            record: 'namespace:container_cpu_usage:sum',
          },
          {
            expr: 'sum(container_memory_usage_bytes{container!="POD",container!="",pod!=""}) BY (cluster) / sum(machine_memory_bytes) BY (cluster)',
            record: 'cluster:memory_usage:ratio',
          },
          {
            expr: 'sum(container_spec_cpu_shares{container!="POD",container!="",pod!=""}) / 1000 / sum(machine_cpu_cores)',
            record: 'cluster:container_spec_cpu_shares:ratio',
          },
          {
            expr: 'sum(rate(container_cpu_usage_seconds_total{container!="POD",container!="",pod!=""}[5m])) / sum(machine_cpu_cores)',
            record: 'cluster:container_cpu_usage:ratio',
          },
          {
            expr: 'kube_node_labels and on(node) kube_node_role{role="master"}',
            labels: {
              label_node_role_kubernetes_io: 'master',
              label_node_role_kubernetes_io_master: 'true',
            },
            record: 'cluster:master_nodes',
          },
          {
            expr: 'kube_node_labels and on(node) kube_node_role{role="infra"}',
            labels: {
              label_node_role_kubernetes_io_infra: 'true',
            },
            record: 'cluster:infra_nodes',
          },
          {
            expr: 'cluster:master_nodes and on(node) cluster:infra_nodes',
            labels: {
              label_node_role_kubernetes_io_master: 'true',
              label_node_role_kubernetes_io_infra: 'true',
            },
            record: 'cluster:master_infra_nodes',
          },
          {
            expr: 'cluster:master_infra_nodes or on (node) cluster:master_nodes or on (node) cluster:infra_nodes or on (node) kube_node_labels',
            record: 'cluster:nodes_roles',
          },
          {
            expr: 'sum((cluster:master_nodes * on(node) group_left kube_node_status_capacity_cpu_cores) or on(node) (kube_node_labels * on(node) group_left kube_node_status_capacity_cpu_cores)) BY (label_beta_kubernetes_io_instance_type, label_node_role_kubernetes_io)',
            record: 'cluster:capacity_cpu_cores:sum',
          },
          {
            expr: 'sum((cluster:master_nodes * on(node) group_left kube_node_status_capacity_memory_bytes) or on(node) (kube_node_labels * on(node) group_left kube_node_status_capacity_memory_bytes)) BY (label_beta_kubernetes_io_instance_type, label_node_role_kubernetes_io)',
            record: 'cluster:capacity_memory_bytes:sum',
          },
          {
            expr: 'sum(1 - rate(node_cpu_seconds_total{mode="idle"}[2m]) * on(namespace, pod) group_left(node) node_namespace_pod:kube_pod_info:{})',
            record: 'cluster:cpu_usage_cores:sum',
          },
          {
            expr: 'sum(node_memory_MemTotal_bytes{job="node-exporter"} - node_memory_MemAvailable_bytes{job="node-exporter"})',
            record: 'cluster:memory_usage_bytes:sum',
          },
          {
            expr: 'sum(rate(container_cpu_usage_seconds_total{namespace!~"openshift-.+",pod!="",container=""}[5m]))',
            record: 'workload:cpu_usage_cores:sum',
          },
          {
            expr: 'cluster:cpu_usage_cores:sum - workload:cpu_usage_cores:sum',
            record: 'openshift:cpu_usage_cores:sum',
          },
          {
            expr: 'sum(container_memory_working_set_bytes{namespace!~"openshift-.+",pod!="",container=""})',
            record: 'workload:memory_usage_bytes:sum',
          },
          {
            expr: 'cluster:memory_usage_bytes:sum - workload:memory_usage_bytes:sum',
            record: 'openshift:memory_usage_bytes:sum',
          },
          {
            expr: 'sum(cluster:master_nodes or on(node) kube_node_labels ) BY (label_beta_kubernetes_io_instance_type, label_node_role_kubernetes_io)',
            record: 'cluster:node_instance_type_count:sum',
          },
          {
            expr: 'sum(etcd_object_counts) BY (instance)',
            record: 'instance:etcd_object_counts:sum',
          },
          {
            expr: |||
              sum(cluster:nodes_roles * on (node) group_left() kube_node_status_capacity_cpu_cores)
              by (label_node_openshift_io_os_id, label_kubernetes_io_arch, label_beta_kubernetes_io_instance_type, label_node_role_kubernetes_io_master, label_node_role_kubernetes_io_infra)
            |||,
            record: 'cluster:capacity_cpus:sum',
          },
          {
            expr: |||
              sum(cluster:nodes_roles * on (node) group_left() ( label_replace( (sum (max (node_cpu_info) by (instance, package, core) ) by (instance) ), "node", "$1", "instance", "(.*)" ) ) )
              by (label_node_openshift_io_os_id, label_kubernetes_io_arch, label_beta_kubernetes_io_instance_type, label_node_role_kubernetes_io_master, label_node_role_kubernetes_io_infra)
            |||,
            record: 'cluster:capacity_cores:sum',
          },
          {
            expr: |||
              sum(cluster:nodes_roles * on (node) group_left() ( label_replace( (max (node_cpu_info) by (instance, package) ), "node", "$1", "instance", "(.*)" ) ) )
              by (label_node_openshift_io_os_id, label_kubernetes_io_arch, label_beta_kubernetes_io_instance_type, label_node_role_kubernetes_io_master, label_node_role_kubernetes_io_infra)
            |||,
            record: 'cluster:capacity_cpu_sockets:sum',
          },
          {
            expr: 'rate(cluster_monitoring_operator_reconcile_errors_total[15m]) * 100 / rate(cluster_monitoring_operator_reconcile_attempts_total[15m]) > 10',
            alert: 'ClusterMonitoringOperatorReconciliationErrors',
            'for': '30m',
            annotations: {
              message: 'Cluster Monitoring Operator is experiencing reconciliation error rate of {{ printf "%0.0f" $value }}%.',
            },
            labels: {
              severity: 'warning',
            },
          },
        ],
      },
      {
        name: 'openshift-ingress.rules',
        rules: [
          {
            expr: 'sum by (code) (rate(haproxy_server_http_responses_total[5m]) > 0)',
            record: 'code:cluster:ingress_http_request_count:rate5m:sum',
          },
          {
            expr: 'sum by (frontend) (rate(haproxy_frontend_bytes_in_total[5m]))',
            record: 'frontend:cluster:ingress_frontend_bytes_in:rate5m:sum',
          },
          {
            expr: 'sum by (frontend) (rate(haproxy_frontend_bytes_out_total[5m]))',
            record: 'frontend:cluster:ingress_frontend_bytes_out:rate5m:sum',
          },
          {
            expr: 'sum by (frontend) (haproxy_frontend_current_sessions)',
            record: 'frontend:cluster:ingress_frontend_connections:sum',
          }
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
            expr: 'sum(rate(apiserver_request_count{job="apiserver"}[10m])) BY (code)',
            record: 'code:apiserver_request_count:rate:sum',
          },
          {
            expr: 'sum(rate(apiserver_request_count{job="apiserver",resource=~"image.*",verb!="WATCH"}[10m])) BY (code)',
            record: 'code:registry_api_request_count:rate:sum',
          },
          {
            expr: 'sum(kube_pod_status_ready{condition="true",namespace="openshift-etcd",pod=~"etcd.*"}) by(condition)',
            record: 'kube_pod_status_ready:etcd:sum',
          },
          {
            expr: 'sum(kube_pod_status_ready{condition="true",namespace="openshift-image-registry",pod=~"image-registry.*"}) by(condition)',
            record: 'kube_pod_status_ready:image_registry:sum',
          },
        ],
      },
    ],
  },
}
