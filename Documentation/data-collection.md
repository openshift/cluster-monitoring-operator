# OpenShift 4 Data Collection

Red Hat values our customer experience and privacy. It is important to us that our customers understand exactly what we are sending back to engineering and why. During the developer preview or beta release of our software, we want to be able to make changes to our designs and coding practices in real-time based on customer environments. The faster the feedback loop during these development stages the better.

For the OpenShift 4 Developer Preview we will be sending back these exact attributes based on your cluster ID and pull secret from Red Hat:

[embedmd]:# (../manifests/0000_50_cluster_monitoring_operator_04-config.yaml)
```yaml
apiVersion: v1
data:
  metrics.yaml: |-
    "matches":
    - "{__name__=~\"cluster:usage:.*\"}"
    - "{__name__=\"up\"}"
    - "{__name__=\"cluster_version\"}"
    - "{__name__=\"cluster_version_available_updates\"}"
    - "{__name__=\"cluster_operator_up\"}"
    - "{__name__=\"cluster_operator_conditions\"}"
    - "{__name__=\"cluster_version_payload\"}"
    - "{__name__=\"cluster_installer\"}"
    - "{__name__=\"cluster_infrastructure_provider\"}"
    - "{__name__=\"cluster_feature_set\"}"
    - "{__name__=\"node_uname_info\"}"
    - "{__name__=\"instance:etcd_object_counts:sum\"}"
    - "{__name__=\"ALERTS\",alertstate=\"firing\"}"
    - "{__name__=\"code:apiserver_request_count:rate:sum\"}"
    - "{__name__=\"cluster:capacity_cpu_cores:sum\"}"
    - "{__name__=\"cluster:capacity_memory_bytes:sum\"}"
    - "{__name__=\"cluster:cpu_usage_cores:sum\"}"
    - "{__name__=\"cluster:memory_usage_bytes:sum\"}"
    - "{__name__=\"openshift:cpu_usage_cores:sum\"}"
    - "{__name__=\"openshift:memory_usage_bytes:sum\"}"
    - "{__name__=\"workload:cpu_usage_cores:sum\"}"
    - "{__name__=\"workload:memory_usage_bytes:sum\"}"
    - "{__name__=\"cluster:virt_platform_nodes:sum\"}"
    - "{__name__=\"cluster:node_instance_type_count:sum\"}"
    - "{__name__=\"cnv:vmi_status_running:count\"}"
    - "{__name__=\"node_role_os_version_machine:cpu_capacity_cores:sum\"}"
    - "{__name__=\"node_role_os_version_machine:cpu_capacity_sockets:sum\"}"
    - "{__name__=\"subscription_sync_total\"}"
    - "{__name__=\"csv_succeeded\"}"
    - "{__name__=\"csv_abnormal\"}"
    - "{__name__=\"ceph_cluster_total_bytes\"}"
    - "{__name__=\"ceph_cluster_total_used_raw_bytes\"}"
    - "{__name__=\"ceph_health_status\"}"
    - "{__name__=\"job:ceph_osd_metadata:count\"}"
    - "{__name__=\"job:kube_pv:count\"}"
    - "{__name__=\"job:ceph_pools_iops:total\"}"
    - "{__name__=\"job:ceph_pools_iops_bytes:total\"}"
    - "{__name__=\"job:ceph_versions_running:count\"}"
    - "{__name__=\"job:noobaa_total_unhealthy_buckets:sum\"}"
    - "{__name__=\"job:noobaa_bucket_count:sum\"}"
    - "{__name__=\"job:noobaa_total_object_count:sum\"}"
    - "{__name__=\"noobaa_accounts_num\"}"
    - "{__name__=\"noobaa_total_usage\"}"
    - "{__name__=\"console_url\"}"
    - "{__name__=\"cluster:network_attachment_definition_instances:max\"}"
    - "{__name__=\"cluster:network_attachment_definition_enabled_instance_up:max\"}"
    - "{__name__=\"insightsclient_request_send_total\"}"
kind: ConfigMap
metadata:
  name: telemetry-config
  namespace: openshift-monitoring
```

These attributes are focused on the health of the cluster based on the CPU/MEM environmental attributes. From this telemetry we hope to be able to determine the immediate functionality of the framework components and whether or not we have a correlation of issues across similar developer preview environmental characteristics. This information will allow us to immediately make changes to the OpenShift solution to improve our customer's experience and software resiliency.

We are extremely excited about showing you where the product is headed during this developer preview and we hope you will allow us this information to enhance the solution for all those involved.
