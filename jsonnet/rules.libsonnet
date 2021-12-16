local droppedKsmLabels = 'endpoint, instance, job, pod, service';

function(params) {
  local cfg = params._config,

  groups: [
    {
      name: 'openshift-general.rules',
      rules: [
        {
          expr: |||
            100 * (count(up == 0 unless on (node) max by (node) (kube_node_spec_unschedulable == 1)) BY (job, namespace, service) /
              count(up unless on (node) max by (node) (kube_node_spec_unschedulable == 1)) BY (job, namespace, service)) > 10
          |||,
          alert: 'TargetDown',
          'for': '15m',
          annotations: {
            description: '{{ printf "%.4g" $value }}% of the {{ $labels.job }}/{{ $labels.service }} targets in {{ $labels.namespace }} namespace have been unreachable for more than 15 minutes. This may be a symptom of network connectivity issues, down nodes, or failures within these components. Assess the health of the infrastructure and nodes running these targets and then contact support.',
            summary: 'Some targets were not reachable from the monitoring server for an extended period of time.',
          },
          labels: {
            severity: 'warning',
          },
        },
        {
          expr: |||
            count without (node)
            (
              group by (node, workload, namespace)
              (
                kube_pod_info{node!=""}
                * on(namespace,pod) group_left(workload)
                (
                  max by(namespace, pod, workload) (kube_pod_spec_volumes_persistentvolumeclaims_info)
                  * on(namespace,pod) group_left(workload)
                  (
                    namespace_workload_pod:kube_pod_owner:relabel
                    * on(namespace,workload,workload_type) group_left()
                    (
                      count without(pod) (namespace_workload_pod:kube_pod_owner:relabel{%(namespaceSelector)s}) > 1
                    )
                  )
                )
              )
            ) == 1
          ||| % cfg,
          alert: 'HighlyAvailableWorkloadIncorrectlySpread',
          'for': '1h',
          annotations: {
            description: 'Workload {{ $labels.namespace }}/{{ $labels.workload }} is incorrectly spread across multiple nodes which breaks high-availability requirements. Since the workload is using persistent volumes, manual intervention is needed. Please follow the guidelines provided in the runbook of this alert to fix this issue.',
            summary: 'Highly-available workload is incorrectly spread across multiple nodes and manual intervention is needed.',
            runbook_url: 'https://github.com/openshift/runbooks/blob/master/alerts/HighlyAvailableWorkloadIncorrectlySpread.md',
          },
          labels: {
            severity: 'warning',
          },
        },
      ],
    },
    {
      name: 'openshift-kubernetes.rules',
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
                  kube_node_status_capacity{resource="cpu",unit="core"}
                )
              )
              or on(node) (
                max without(endpoint, instance, job, pod, service)
                (
                  kube_node_labels
                ) * on(node) group_left() max by(node)
                (
                  kube_node_status_capacity{resource="cpu",unit="core"}
                )
              )
            )
          |||,
          record: 'cluster:capacity_cpu_cores:sum',
        },
        {
          expr: |||
            clamp_max(
              label_replace(
                sum by(instance, package, core) (
                  node_cpu_info{core!="",package!=""}
                  or
                  # Assume core = cpu and package = 0 for platforms that don't expose core/package labels.
                  label_replace(label_join(node_cpu_info{core="",package=""}, "core", "", "cpu"), "package", "0", "package", "")
                ) > 1,
                "label_node_hyperthread_enabled",
                "true",
                "instance",
                "(.*)"
              ) or on (instance, package)
              label_replace(
                sum by(instance, package, core) (
                  label_replace(node_cpu_info{core!="",package!=""}
                  or
                  # Assume core = cpu and package = 0 for platforms that don't expose core/package labels.
                  label_join(node_cpu_info{core="",package=""}, "core", "", "cpu"), "package", "0", "package", "")
                ) <= 1,
                "label_node_hyperthread_enabled",
                "false",
                "instance",
                "(.*)"
              ),
              1
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
                  kube_node_status_capacity{resource="memory",unit="byte"}
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
                  kube_node_status_capacity{resource="memory",unit="byte"}
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
          expr: |||
            sum by(provisioner) (
              topk by (namespace, persistentvolumeclaim) (
                1, kube_persistentvolumeclaim_resource_requests_storage_bytes
              ) * on(namespace, persistentvolumeclaim) group_right()
              topk by(namespace, persistentvolumeclaim) (
                1, kube_persistentvolumeclaim_info * on(storageclass) group_left(provisioner) topk by(storageclass) (1, max by(storageclass, provisioner) (kube_storageclass_info))
              )
            )
          |||,
          record: 'cluster:kube_persistentvolumeclaim_resource_requests_storage_bytes:provisioner:sum',
        },
        {
          // Track the number of physical cores that are considered accessible for general workloads to run on. A physical core is an unshared CPU as seen by the node operating system, ignoring hyperthreading or virtualization. The sum of all non-infrastructure node physical cores plus master node physical cores (if masters are schedulable) is considered available for workload use.
          expr: '(sum(node_role_os_version_machine:cpu_capacity_cores:sum{label_node_role_kubernetes_io_master="",label_node_role_kubernetes_io_infra=""} or absent(__does_not_exist__)*0)) + ((sum(node_role_os_version_machine:cpu_capacity_cores:sum{label_node_role_kubernetes_io_master="true"} or absent(__does_not_exist__)*0) * ((max(cluster_master_schedulable == 1)*0+1) or (absent(cluster_master_schedulable == 1)*0))))',
          record: 'workload:capacity_physical_cpu_cores:sum',
        },
        {
          // Record the rolling minimum of workload accessible physical CPU cores over a 5m window.
          expr: 'min_over_time(workload:capacity_physical_cpu_cores:sum[5m:15s])',
          record: 'cluster:usage:workload:capacity_physical_cpu_cores:min:5m',
        },
        {
          // Record the rolling maximum of workload accessible physical CPU cores over a 5m window.
          expr: 'max_over_time(workload:capacity_physical_cpu_cores:sum[5m:15s])',
          record: 'cluster:usage:workload:capacity_physical_cpu_cores:max:5m',
        },
        {
          expr: |||
            sum  by (provisioner) (
              topk by (namespace, persistentvolumeclaim) (
                1, kubelet_volume_stats_used_bytes
              ) * on (namespace,persistentvolumeclaim) group_right()
              topk by (namespace, persistentvolumeclaim) (
                1, kube_persistentvolumeclaim_info * on(storageclass) group_left(provisioner) topk by(storageclass) (1, max by(storageclass, provisioner) (kube_storageclass_info))
              )
            )
          |||,
          record: 'cluster:kubelet_volume_stats_used_bytes:provisioner:sum',
        },
        {
          // This recording rule was based on the now deprecated
          // etcd_object_counts metric which explains the name.
          // TODO: rename the recording rule and add it to the telemetry allow-list.
          expr: 'sum by (instance) (apiserver_storage_objects)',
          record: 'instance:etcd_object_counts:sum',
        },
        {
          expr: 'topk(500, max by(resource) (apiserver_storage_objects))',
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
          expr: 'max(alertmanager_integrations{namespace="openshift-monitoring"})',
          record: 'cluster:alertmanager_integrations:max',
        },
        {
          expr: 'sum by(plugin_name, volume_mode)(pv_collector_total_pv_count)',
          record: 'cluster:kube_persistentvolume_plugin_type_counts:sum',
        },
        {
          expr: 'sum by(version)(vsphere_vcenter_info)',
          record: 'cluster:vsphere_vcenter_info:sum',
        },
        {
          expr: 'sum by(version)(vsphere_esxi_version_total)',
          record: 'cluster:vsphere_esxi_version_total:sum',
        },
        {
          expr: 'sum by(hw_version)(vsphere_node_hw_version_total)',
          record: 'cluster:vsphere_node_hw_version_total:sum',
        },
        {
          expr: |||
            sum(
              min by (node) (kube_node_status_condition{condition="Ready",status="true"})
                and
              max by (node) (kube_node_role{role="master"})
            ) == bool sum(kube_node_role{role="master"})
          |||,
          record: 'cluster:control_plane:all_nodes_ready',
          // Returns 1 if all control plane nodes are ready 0 otherwise.
          // Should be used to suppress alerts during control plane upgrades or disruption.
        },
        {
          expr: 'max_over_time(cluster_monitoring_operator_last_reconciliation_successful[5m]) == 0',
          alert: 'ClusterMonitoringOperatorReconciliationErrors',
          'for': '1h',
          annotations: {
            summary: 'Cluster Monitoring Operator is experiencing unexpected reconciliation errors.',
            description: 'Errors are occurring during reconciliation cycles. Inspect the cluster-monitoring-operator log for potential root causes.',
          },
          labels: {
            severity: 'warning',
          },
        },
        {
          expr: 'cluster:alertmanager_integrations:max == 0',
          alert: 'AlertmanagerReceiversNotConfigured',
          'for': '10m',
          annotations: {
            summary: 'Receivers (notification integrations) are not configured on Alertmanager',
            description: 'Alerts are not configured to be sent to a notification system, meaning that you may not be notified in a timely fashion when important failures occur. Check the OpenShift documentation to learn how to configure notifications with Alertmanager.',
          },
          labels: {
            severity: 'warning',
            // All OpenShift alerts should have a namespace label.
            // See: https://issues.redhat.com/browse/MON-939
            namespace: 'openshift-monitoring',
          },
        },
        {
          expr: |||
            (((
              kube_deployment_spec_replicas{%(namespaceSelector)s,job="kube-state-metrics"}
                >
              kube_deployment_status_replicas_available{%(namespaceSelector)s,job="kube-state-metrics"}
            ) and (
              changes(kube_deployment_status_replicas_updated{%(namespaceSelector)s,job="kube-state-metrics"}[5m])
                ==
              0
            )) * on() group_left cluster:control_plane:all_nodes_ready) > 0
          ||| % cfg,
          alert: 'KubeDeploymentReplicasMismatch',
          'for': '15m',
          annotations: {
            description: 'Deployment {{ $labels.namespace }}/{{ $labels.deployment }} has not matched the expected number of replicas for longer than 15 minutes. This indicates that cluster infrastructure is unable to start or restart the necessary components. This most often occurs when one or more nodes are down or partioned from the cluster, or a fault occurs on the node that prevents the workload from starting. In rare cases this may indicate a new version of a cluster component cannot start due to a bug or configuration error. Assess the pods for this deployment to verify they are running on healthy nodes and then contact support.',
            summary: 'Deployment has not matched the expected number of replicas',
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
            summary: 'Containers are being killed due to OOM',
            description: 'Multiple containers were out of memory killed within the past 15 minutes. There are many potential causes of OOM errors, however issues on a specific node or containers breaching their limits is common.',
          },
          labels: {
            severity: 'info',
            // All OpenShift alerts should have a namespace label.
            // See: https://issues.redhat.com/browse/MON-939
            namespace: 'kube-system',
          },
        },
        {
          expr: 'avg_over_time((((count((max by (node) (up{job="kubelet",metrics_path="/metrics"} == 1) and max by (node) (kube_node_status_condition{condition="Ready",status="true"} == 1) and min by (node) (kube_node_spec_unschedulable == 0))) / scalar(count(min by (node) (kube_node_spec_unschedulable == 0))))))[5m:1s])',
          record: 'cluster:usage:kube_schedulable_node_ready_reachable:avg5m',
          // Report a 5m rolling average of the number of schedulable nodes that are ready and reachable to be scraped by metrics. This is
          // used to estimate the disruption imposed on a cluster during upgrades, excluding any machines administrators may be performing
          // maintenance on.
        },
        {
          expr: 'avg_over_time((count(max by (node) (kube_node_status_condition{condition="Ready",status="true"} == 1)) / scalar(count(max by (node) (kube_node_status_condition{condition="Ready",status="true"}))))[5m:1s])',
          record: 'cluster:usage:kube_node_ready:avg5m',
          // Report a 5m rolling average of the number of ready nodes in a cluster. This provides the user-facing measurement of how often
          // nodes report unready, but not represent all possible user-impacting outages to nodes.
        },
        {
          expr: '(max without (condition,container,endpoint,instance,job,service) (((kube_pod_status_ready{condition="false"} == 1)*0 or (kube_pod_status_ready{condition="true"} == 1)) * on(pod,namespace) group_left() group by (pod,namespace) (kube_pod_status_phase{phase=~"Running|Unknown|Pending"} == 1)))',
          record: 'kube_running_pod_ready',
          // For all non-terminal pods, report ready pods with 1 and unready pods with 0
        },
        {
          expr: 'avg(kube_running_pod_ready{namespace=~"openshift-.*"})',
          record: 'cluster:usage:openshift:kube_running_pod_ready:avg',
          // Report the percentage (0-1) of pending or running openshift pods reporting ready
        },
        {
          expr: 'avg(kube_running_pod_ready{namespace!~"openshift-.*"})',
          record: 'cluster:usage:workload:kube_running_pod_ready:avg',
          // Report the percentage (0-1) of pending or running workload (everything outside of openshift-*) pods reporting ready
        },
      ],
    },
    {
      name: 'kubernetes-recurring.rules',
      interval: '30s',
      rules: [
        {
          // Count the number of accumulated workload core/seconds continuously. This makes reading and measuring
          // consumption more efficient at the cluster and aggregate levels. In general this may underestimate the
          // actual consumption, but never overestimate consumption.
          expr: 'sum_over_time(workload:capacity_physical_cpu_cores:sum[30s:1s]) + ((cluster:usage:workload:capacity_physical_cpu_core_seconds offset 25s) or (absent(cluster:usage:workload:capacity_physical_cpu_core_seconds offset 25s)*0))',
          record: 'cluster:usage:workload:capacity_physical_cpu_core_seconds',
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
          expr: 'sum (rate(haproxy_frontend_bytes_in_total[5m]))',
          record: 'cluster:usage:ingress_frontend_bytes_in:rate5m:sum',
          // The rate of bytes in through the ingress frontends
        },
        {
          expr: 'sum (rate(haproxy_frontend_bytes_out_total[5m]))',
          record: 'cluster:usage:ingress_frontend_bytes_out:rate5m:sum',
          // The rate of bytes out through the ingress frontends
        },
        {
          expr: 'sum (haproxy_frontend_current_sessions)',
          record: 'cluster:usage:ingress_frontend_connections:sum',
          // The number of open connections on the ingress frontends
        },
        {
          expr: 'sum(max without(service,endpoint,container,pod,job,namespace) (increase(haproxy_server_http_responses_total{code!~"2xx|1xx|4xx|3xx",exported_namespace!~"openshift-.*"}[5m]) > 0)) / sum (max without(service,endpoint,container,pod,job,namespace) (increase(haproxy_server_http_responses_total{exported_namespace!~"openshift-.*"}[5m]))) or absent(__does_not_exist__)*0',
          record: 'cluster:usage:workload:ingress_request_error:fraction5m',
          // The fraction of workload requests that have errored over the last five minutes, measured at the ingress controllers
        },
        {
          expr: 'sum (max without(service,endpoint,container,pod,job,namespace) (irate(haproxy_server_http_responses_total{exported_namespace!~"openshift-.*"}[5m]))) or absent(__does_not_exist__)*0',
          record: 'cluster:usage:workload:ingress_request_total:irate5m',
          // The instantaneous rate of workload requests per second arriving at the ingress controllers
        },
        {
          expr: 'sum(max without(service,endpoint,container,pod,job,namespace) (increase(haproxy_server_http_responses_total{code!~"2xx|1xx|4xx|3xx",exported_namespace=~"openshift-.*"}[5m]) > 0)) / sum (max without(service,endpoint,container,pod,job,namespace) (increase(haproxy_server_http_responses_total{exported_namespace=~"openshift-.*"}[5m]))) or absent(__does_not_exist__)*0',
          record: 'cluster:usage:openshift:ingress_request_error:fraction5m',
          // The fraction of openshift requests that have errored over the last five minutes, measured at the ingress controllers
        },
        {
          expr: 'sum (max without(service,endpoint,container,pod,job,namespace) (irate(haproxy_server_http_responses_total{exported_namespace=~"openshift-.*"}[5m]))) or absent(__does_not_exist__)*0',
          record: 'cluster:usage:openshift:ingress_request_total:irate5m',
          // The instantaneous rate of openshift requests per second arriving at the ingress controllers
        },
        {
          expr: 'sum(ingress_controller_aws_nlb_active) or vector(0)',
          record: 'cluster:ingress_controller_aws_nlb_active:sum',
          // Informs how many NLBs are active in AWS.
        },
      ],
    },
    {
      name: 'openshift-build.rules',
      rules: [
        {
          expr: 'sum by (strategy) (openshift_build_status_phase_total)',
          record: 'openshift:build_by_strategy:sum',
        },
      ],
    },
    {
      name: 'openshift-monitoring.rules',
      rules: [
        {
          // We use "... (max without(instance) ...)" to avoid double
          // accounting when the Prometheus pods are restarted and persistent
          // storage is used. Because of staleness handling, series for the
          // old pods will continue to exist for 5 minutes.
          expr: 'sum by (job,namespace) (max without(instance) (prometheus_tsdb_head_series{namespace=~"openshift-monitoring|openshift-user-workload-monitoring"}))',
          record: 'openshift:prometheus_tsdb_head_series:sum',
        },
        {
          // See comment above for the explanation about using "... (max without(instance) ...)".
          expr: 'sum by(job,namespace) (max without(instance) (rate(prometheus_tsdb_head_samples_appended_total{namespace=~"openshift-monitoring|openshift-user-workload-monitoring"}[2m])))',
          record: 'openshift:prometheus_tsdb_head_samples_appended_total:sum',
        },
        {
          // See comment above for the explanation about using "... (max without(instance) ...)".
          expr: 'sum by (namespace) (max without(instance) (container_memory_working_set_bytes{namespace=~"openshift-monitoring|openshift-user-workload-monitoring", container=""}))',
          record: 'monitoring:container_memory_working_set_bytes:sum',
        },
        {
          // For each (namespace, job) pair, sum the number of series added over the past hour, then filter the top 3 items.
          expr: 'topk(3, sum by(namespace, job)(sum_over_time(scrape_series_added[1h])))',
          record: 'namespace_job:scrape_series_added:topk3_sum1h',
        },
        {
          // For each (namespace, job) pair, return the target producing the highest number of samples, then filter the top 3 items.
          expr: 'topk(3, max by(namespace, job) (topk by(namespace,job) (1, scrape_samples_post_metric_relabeling)))',
          record: 'namespace_job:scrape_samples_post_metric_relabeling:topk3',
        },
        {
          expr: 'sum by(exported_service) (rate(haproxy_server_http_responses_total{exported_namespace="openshift-monitoring", exported_service=~"alertmanager-main|grafana|prometheus-k8s"}[5m]))',
          record: 'monitoring:haproxy_server_http_responses_total:sum',
        },
        {
          expr: 'max by (cluster, namespace, workload, pod) (label_replace(label_replace(kube_pod_owner{job="kube-state-metrics", owner_kind="ReplicationController"},"replicationcontroller", "$1", "owner_name", "(.*)") * on(replicationcontroller, namespace) group_left(owner_name) topk by(replicationcontroller, namespace) (1, max by (replicationcontroller, namespace, owner_name) (kube_replicationcontroller_owner{job="kube-state-metrics"})),"workload", "$1", "owner_name", "(.*)"))',
          labels: { workload_type: 'deploymentconfig' },
          record: 'namespace_workload_pod:kube_pod_owner:relabel',
        },
      ],
    },
    {
      name: 'openshift-etcd-telemetry.rules',
      rules: [
        {
          expr: 'sum by (instance) (etcd_mvcc_db_total_size_in_bytes{job="etcd"})',
          record: 'instance:etcd_mvcc_db_total_size_in_bytes:sum',
        },
        {
          expr: 'histogram_quantile(0.99, sum by (instance, le) (rate(etcd_disk_wal_fsync_duration_seconds_bucket{job="etcd"}[5m])))',
          labels: {
            quantile: '0.99',
          },
          record: 'instance:etcd_disk_wal_fsync_duration_seconds:histogram_quantile',
        },
        {
          expr: 'histogram_quantile(0.99, sum by (instance, le) (rate(etcd_network_peer_round_trip_time_seconds_bucket{job="etcd"}[5m])))',
          labels: {
            quantile: '0.99',
          },
          record: 'instance:etcd_network_peer_round_trip_time_seconds:histogram_quantile',
        },
        {
          expr: 'sum by (instance) (etcd_mvcc_db_total_size_in_use_in_bytes{job="etcd"})',
          record: 'instance:etcd_mvcc_db_total_size_in_use_in_bytes:sum',
        },
        {
          expr: 'histogram_quantile(0.99, sum by (instance, le) (rate(etcd_disk_backend_commit_duration_seconds_bucket{job="etcd"}[5m])))',
          labels: {
            quantile: '0.99',
          },
          record: 'instance:etcd_disk_backend_commit_duration_seconds:histogram_quantile',
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
      ],
    },
  ],
}
