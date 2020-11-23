local droppedKsmLabels = 'endpoint, instance, job, pod, service';

{
  prometheusRules+:: {
    groups+: [
      {
        name: 'kubernetes.rules',
        rules: [
          {
            expr: 'sum(container_memory_usage_bytes{container="",pod!=""}) BY (pod, namespace)',
            record: 'pod:container_memory_usage_bytes:sum',
          },
          {
            expr: 'sum(container_spec_cpu_shares{container="",pod!=""}) BY (pod, namespace)',
            record: 'pod:container_spec_cpu_shares:sum',
          },
          {
            expr: 'sum(rate(container_cpu_usage_seconds_total{container="",pod!=""}[5m])) BY (pod, namespace)',
            record: 'pod:container_cpu_usage:sum',
          },
          {
            expr: 'sum(container_fs_usage_bytes{pod!=""}) BY (pod, namespace)',
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
            expr: 'sum(container_memory_usage_bytes{container="",pod!=""}) BY (cluster) / sum(machine_memory_bytes) BY (cluster)',
            record: 'cluster:memory_usage:ratio',
          },
          {
            expr: 'sum(container_spec_cpu_shares{container="",pod!=""}) / 1000 / sum(machine_cpu_cores)',
            record: 'cluster:container_spec_cpu_shares:ratio',
          },
          {
            expr: 'sum(rate(container_cpu_usage_seconds_total{container="",pod!=""}[5m])) / sum(machine_cpu_cores)',
            record: 'cluster:container_cpu_usage:ratio',
          },
          {
            expr: 'max without(%s) (kube_node_labels and on(node) kube_node_role{role="master"})' % droppedKsmLabels,
            labels: {
              label_node_role_kubernetes_io: 'master',
              label_node_role_kubernetes_io_master: 'true',
            },
            record: 'cluster:master_nodes',
          },
          {
            expr: 'max without(%s) (kube_node_labels and on(node) kube_node_role{role="infra"})' % droppedKsmLabels,
            labels: {
              label_node_role_kubernetes_io_infra: 'true',
            },
            record: 'cluster:infra_nodes',
          },
          {
            expr: 'max without(%s) (cluster:master_nodes and on(node) cluster:infra_nodes)' % droppedKsmLabels,
            labels: {
              label_node_role_kubernetes_io_master: 'true',
              label_node_role_kubernetes_io_infra: 'true',
            },
            record: 'cluster:master_infra_nodes',
          },
          {
            expr: 'cluster:master_infra_nodes or on (node) cluster:master_nodes or on (node) cluster:infra_nodes or on (node) max without(%s) (kube_node_labels)' % droppedKsmLabels,
            record: 'cluster:nodes_roles',
          },
          {
            expr: 'kube_node_labels and on(node) (sum(label_replace(node_cpu_info, "node", "$1", "instance", "(.*)")) by (node, package, core) == 2)',
            labels: {
              label_node_hyperthread_enabled: 'true',
            },
            record: 'cluster:hyperthread_enabled_nodes',
          },
          {
            expr: 'count(sum(virt_platform) by (instance, type, system_manufacturer, system_product_name, baseboard_manufacturer, baseboard_product_name)) by (type, system_manufacturer, system_product_name, baseboard_manufacturer, baseboard_product_name)',
            record: 'cluster:virt_platform_nodes:sum',
          },
          {
            expr: |||
              sum by(label_beta_kubernetes_io_instance_type, label_node_role_kubernetes_io, label_kubernetes_io_arch, label_node_openshift_io_os_id) (
                (
                  cluster:master_nodes
                  * on(node) group_left() max by(node)
                  (
                    kube_node_status_capacity_cpu_cores
                  )
                )
                or on(node) (
                  max without(endpoint, instance, job, pod, service)
                  (
                    kube_node_labels
                  ) * on(node) group_left() max by(node)
                  (
                    kube_node_status_capacity_cpu_cores
                  )
                )
              )
            |||,
            record: 'cluster:capacity_cpu_cores:sum',
          },
          {
            expr: |||
              clamp_max(
                (
                  label_replace( ( ( sum (node_cpu_info) by (instance, package, core) )  > 1 ), "label_node_hyperthread_enabled", "true", "instance", "(.*)" )
                  or on (instance, package)
                  label_replace( ( ( sum (node_cpu_info) by (instance, package, core) ) <= 1 ), "label_node_hyperthread_enabled", "false", "instance", "(.*)" )
                ), 1
              )
            |||,
            record: 'cluster:cpu_core_hyperthreading',
          },
          {
            expr: |||
              topk by(node) (1, cluster:nodes_roles) * on (node)
                group_right( label_beta_kubernetes_io_instance_type, label_node_role_kubernetes_io, label_node_openshift_io_os_id, label_kubernetes_io_arch,
                             label_node_role_kubernetes_io_master, label_node_role_kubernetes_io_infra)
              label_replace( cluster:cpu_core_hyperthreading, "node", "$1", "instance", "(.*)" )
            |||,
            record: 'cluster:cpu_core_node_labels',
          },
          {
            expr: 'count(cluster:cpu_core_node_labels) by (label_beta_kubernetes_io_instance_type, label_node_hyperthread_enabled)',
            record: 'cluster:capacity_cpu_cores_hyperthread_enabled:sum',
          },
          {
            expr: |||
              sum by(label_beta_kubernetes_io_instance_type, label_node_role_kubernetes_io)
              (
                (
                  cluster:master_nodes
                  * on(node) group_left() max by(node)
                  (
                    kube_node_status_capacity_memory_bytes
                  )
                )
                or on(node)
                (
                  max without(endpoint, instance, job, pod, service)
                  (
                    kube_node_labels
                  )
                  * on(node) group_left() max by(node)
                  (
                    kube_node_status_capacity_memory_bytes
                  )
                )
              )
            |||,
            record: 'cluster:capacity_memory_bytes:sum',
          },
          {
            expr: 'sum(1 - rate(node_cpu_seconds_total{mode="idle"}[2m]) * on(namespace, pod) group_left(node) node_namespace_pod:kube_pod_info:{pod=~"node-exporter.+"})',
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
            expr: 'sum(cluster:master_nodes or on(node) kube_node_labels ) BY (label_beta_kubernetes_io_instance_type, label_node_role_kubernetes_io, label_kubernetes_io_arch, label_node_openshift_io_os_id)',
            record: 'cluster:node_instance_type_count:sum',
          },
          {
            expr: 'sum  by (provisioner) (kube_persistentvolumeclaim_resource_requests_storage_bytes * on (namespace,persistentvolumeclaim) group_right() (kube_persistentvolumeclaim_info * on (storageclass)  group_left(provisioner) kube_storageclass_info))',
            record: 'cluster:kube_persistentvolumeclaim_resource_requests_storage_bytes:provisioner:sum',
          },
          {
            expr: 'sum  by (provisioner) (kubelet_volume_stats_used_bytes * on (namespace,persistentvolumeclaim) group_right() (kube_persistentvolumeclaim_info * on (storageclass)  group_left(provisioner) kube_storageclass_info))',
            record: 'cluster:kubelet_volume_stats_used_bytes:provisioner:sum',
          },
          {
            expr: 'sum(etcd_object_counts) BY (instance)',
            record: 'instance:etcd_object_counts:sum',
          },
          {
            expr: 'topk(500, max(etcd_object_counts) by (resource))',
            record: 'cluster:usage:resources:sum',
          },
          {
            expr: 'count(count (kube_pod_restart_policy{type!="Always",namespace!~"openshift-.+"}) by (namespace,pod))',
            record: 'cluster:usage:pods:terminal:workload:sum',
          },
          {
            expr: 'sum(max(kubelet_containers_per_pod_count_sum) by (instance))',
            record: 'cluster:usage:containers:sum',
          },
          {
            expr: 'count(cluster:cpu_core_node_labels) by (label_kubernetes_io_arch, label_node_hyperthread_enabled, label_node_openshift_io_os_id,label_node_role_kubernetes_io_master,label_node_role_kubernetes_io_infra)',
            record: 'node_role_os_version_machine:cpu_capacity_cores:sum',
          },
          {
            expr: 'count(max(cluster:cpu_core_node_labels) by (node, package, label_beta_kubernetes_io_instance_type, label_node_hyperthread_enabled, label_node_role_kubernetes_io) ) by ( label_beta_kubernetes_io_instance_type, label_node_hyperthread_enabled, label_node_role_kubernetes_io)',
            record: 'cluster:capacity_cpu_sockets_hyperthread_enabled:sum',
          },
          {
            expr: 'count (max(cluster:cpu_core_node_labels) by (node, package, label_kubernetes_io_arch, label_node_hyperthread_enabled, label_node_openshift_io_os_id,label_node_role_kubernetes_io_master,label_node_role_kubernetes_io_infra) ) by (label_kubernetes_io_arch, label_node_hyperthread_enabled, label_node_openshift_io_os_id,label_node_role_kubernetes_io_master,label_node_role_kubernetes_io_infra)',
            record: 'node_role_os_version_machine:cpu_capacity_sockets:sum',
          },
          {
            expr: 'clamp_max(sum(alertmanager_notifications_total),1)',
            record: 'cluster:alertmanager_routing_enabled:max',
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
          {
            expr: 'cluster:alertmanager_routing_enabled:max == 0',
            alert: 'AlertmanagerReceiversNotConfigured',
            'for': '10m',
            annotations: {
              message: 'Alerts are not configured to be sent to a notification system, meaning that you may not be notified in a timely fashion when important failures occur. Check the OpenShift documentation to learn how to configure notifications with Alertmanager.',
            },
            labels: {
              severity: 'warning',
            },
          },
          {
            expr: 'sum(max by(namespace, container, pod) (increase(kube_pod_container_status_restarts_total[12m])) and max by(namespace, container, pod) (kube_pod_container_status_last_terminated_reason{reason="OOMKilled"}) == 1) > 5',
            alert: 'MultipleContainersOOMKilled',
            'for': '15m',
            annotations: {
              message: 'Multiple containers were out of memory killed within the past 15 minutes.',
            },
            labels: {
              severity: 'info',
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
        name: 'openshift-monitoring.rules',
        rules: [
          {
            expr: 'sum by (job,namespace) (prometheus_tsdb_head_series{namespace=~"openshift-monitoring|openshift-user-workload-monitoring"})',
            record: 'openshift:prometheus_tsdb_head_series:sum',
          },
          {
            expr: 'sum by(job,namespace) (rate(prometheus_tsdb_head_samples_appended_total{namespace=~"openshift-monitoring|openshift-user-workload-monitoring"}[2m]))',
            record: 'openshift:prometheus_tsdb_head_samples_appended_total:sum',
          },
          {
            expr: 'sum by (namespace) (container_memory_working_set_bytes{namespace=~"openshift-monitoring|openshift-user-workload-monitoring", container=""})',
            record: 'monitoring:container_memory_working_set_bytes:sum',
          },
          {
            expr: 'sum by(exported_service) (rate(haproxy_server_http_responses_total{exported_namespace="openshift-monitoring", exported_service=~"alertmanager-main|grafana|prometheus-k8s"}[5m]))',
            record: 'monitoring:haproxy_server_http_responses_total:sum',
          },
        ],
      },
      {
        name: 'openshift-sre.rules',
        rules: [
          {
            expr: 'sum(rate(apiserver_request_total{job="apiserver"}[10m])) BY (code)',
            record: 'code:apiserver_request_total:rate:sum',
          },
          {
            expr: 'sum(rate(apiserver_request_total{job="apiserver",resource=~"image.*",verb!="WATCH"}[10m])) BY (code)',
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
