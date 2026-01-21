// This is the user-facing file for adding telemetry entries.

// Ignorelist for existing entries that use empty (unknown) monitor keys.
//
// New entries must try to avoid using empty monitor keys. If a metric is from
// an unknown monitor, please identify the correct monitor(s) and drop the rule
// from this list.
local unknownMonitorIgnorelist = {
  '{__name__="monitoring:haproxy_server_http_responses_total:sum"}': true,
  '{__name__="cluster_version"}': true,
  '{__name__="cluster_version_available_updates"}': true,
  '{__name__="cluster_version_capability"}': true,
  '{__name__="cluster_operator_up"}': true,
  '{__name__="cluster_operator_conditions"}': true,
  '{__name__="cluster_version_payload"}': true,
  '{__name__="cluster_installer"}': true,
  '{__name__="cluster_infrastructure_provider"}': true,
  '{__name__="cluster_feature_set"}': true,
  '{__name__="cnv:vmi_status_running:count"}': true,
  '{__name__="cnv_abnormal", reason=~"memory_working_set_delta_from_request|memory_rss_delta_from_request"}': true,
  '{__name__="subscription_sync_total"}': true,
  '{__name__="olm_resolution_duration_seconds"}': true,
  '{__name__="csv_succeeded"}': true,
  '{__name__="csv_abnormal"}': true,
  '{__name__="ceph_cluster_total_bytes"}': true,
  '{__name__="ceph_cluster_total_used_raw_bytes"}': true,
  '{__name__="ceph_health_status"}': true,
  '{__name__="odf_system_raw_capacity_total_bytes"}': true,
  '{__name__="odf_system_raw_capacity_used_bytes"}': true,
  '{__name__="odf_system_health_status"}': true,
  '{__name__="job:ceph_osd_metadata:count"}': true,
  '{__name__="job:ceph_pools_iops:total"}': true,
  '{__name__="job:ceph_pools_iops_bytes:total"}': true,
  '{__name__="job:ceph_versions_running:count"}': true,
  '{__name__="job:noobaa_total_unhealthy_buckets:sum"}': true,
  '{__name__="job:noobaa_bucket_count:sum"}': true,
  '{__name__="job:noobaa_total_object_count:sum"}': true,
  '{__name__="odf_system_bucket_count", system_type="OCS", system_vendor="Red Hat"}': true,
  '{__name__="odf_system_objects_total", system_type="OCS", system_vendor="Red Hat"}': true,
  '{__name__="noobaa_accounts_num"}': true,
  '{__name__="noobaa_total_usage"}': true,
  '{__name__="console_url"}': true,
  '{__name__="cluster:console_auth_login_requests_total:sum"}': true,
  '{__name__="cluster:console_auth_login_successes_total:sum"}': true,
  '{__name__="cluster:console_auth_login_failures_total:sum"}': true,
  '{__name__="cluster:console_auth_logout_requests_total:sum"}': true,
  '{__name__="cluster:console_usage_users:max"}': true,
  '{__name__="cluster:console_plugins_info:max"}': true,
  '{__name__="cluster:console_customization_perspectives_info:max"}': true,
  '{__name__="cluster:ovnkube_controller_egress_routing_via_host:max"}': true,
  '{__name__="cluster:ovnkube_controller_admin_network_policies_db_objects:max",table_name=~"ACL|Address_Set"}': true,
  '{__name__="cluster:ovnkube_controller_baseline_admin_network_policies_db_objects:max",table_name=~"ACL|Address_Set"}': true,
  '{__name__="cluster:ovnkube_controller_admin_network_policies_rules:max",direction=~"Ingress|Egress",action=~"Pass|Allow|Deny"}': true,
  '{__name__="cluster:ovnkube_controller_baseline_admin_network_policies_rules:max",direction=~"Ingress|Egress",action=~"Allow|Deny"}': true,
  '{__name__="cluster:network_attachment_definition_instances:max"}': true,
  '{__name__="cluster:network_attachment_definition_enabled_instance_up:max"}': true,
  '{__name__="cluster:ingress_controller_aws_nlb_active:sum"}': true,
  '{__name__="cluster:route_metrics_controller_routes_per_shard:min"}': true,
  '{__name__="cluster:route_metrics_controller_routes_per_shard:max"}': true,
  '{__name__="cluster:route_metrics_controller_routes_per_shard:avg"}': true,
  '{__name__="cluster:route_metrics_controller_routes_per_shard:median"}': true,
  '{__name__="insightsclient_request_send_total"}': true,
  '{__name__="cam_app_workload_migrations"}': true,
  '{__name__="rhmi_status"}': true,
  '{__name__="state:rhoam_critical_alerts:max"}': true,
  '{__name__="state:rhoam_warning_alerts:max"}': true,
  '{__name__="rhoam_7d_slo_percentile:max"}': true,
  '{__name__="rhoam_7d_slo_remaining_error_budget:max"}': true,
  '{__name__="cluster_legacy_scheduler_policy"}': true,
  '{__name__="cluster_master_schedulable"}': true,
  '{__name__="che_workspace_status"}': true,
  '{__name__="che_workspace_started_total"}': true,
  '{__name__="che_workspace_failure_total"}': true,
  '{__name__="che_workspace_start_time_seconds_sum"}': true,
  '{__name__="che_workspace_start_time_seconds_count"}': true,
  '{__name__="cco_credentials_mode"}': true,
  '{__name__="acm_managed_cluster_info"}': true,
  '{__name__="acm_managed_cluster_worker_cores:max"}': true,
  '{__name__="acm_console_page_count:sum", page=~"overview-classic|overview-fleet|search|search-details|clusters|application|governance"}': true,
  '{__name__="cluster:vsphere_vcenter_info:sum"}': true,
  '{__name__="cluster:vsphere_esxi_version_total:sum"}': true,
  '{__name__="cluster:vsphere_node_hw_version_total:sum"}': true,
  '{__name__="rhods_aggregate_availability"}': true,
  '{__name__="rhods_total_users"}': true,
  '{__name__="instance:etcd_disk_wal_fsync_duration_seconds:histogram_quantile",quantile="0.99"}': true,
  '{__name__="instance:etcd_mvcc_db_total_size_in_bytes:sum"}': true,
  '{__name__="instance:etcd_network_peer_round_trip_time_seconds:histogram_quantile",quantile="0.99"}': true,
  '{__name__="instance:etcd_mvcc_db_total_size_in_use_in_bytes:sum"}': true,
  '{__name__="instance:etcd_disk_backend_commit_duration_seconds:histogram_quantile",quantile="0.99"}': true,
  '{__name__="jaeger_operator_instances_storage_types"}': true,
  '{__name__="jaeger_operator_instances_strategies"}': true,
  '{__name__="jaeger_operator_instances_agent_strategies"}': true,
  '{__name__="type:tempo_operator_tempostack_storage_backend:sum",type=~"azure|gcs|s3"}': true,
  '{__name__="state:tempo_operator_tempostack_managed:sum",state=~"Managed|Unmanaged"}': true,
  '{__name__="type:tempo_operator_tempostack_multi_tenancy:sum",type=~"static|openshift|disabled"}': true,
  '{__name__="enabled:tempo_operator_tempostack_jaeger_ui:sum",enabled=~"true|false"}': true,
  '{__name__="type:opentelemetry_collector_receivers:sum",type=~"jaeger|hostmetrics|opencensus|prometheus|zipkin|kafka|filelog|journald|k8sevents|kubeletstats|k8scluster|k8sobjects|otlp"}': true,
  '{__name__="type:opentelemetry_collector_exporters:sum",type=~"debug|logging|otlp|otlphttp|prometheus|lokiexporter|kafka|awscloudwatchlogs|loadbalancing"}': true,
  '{__name__="type:opentelemetry_collector_processors:sum",type=~"batch|memorylimiter|attributes|resource|span|k8sattributes|resourcedetection|filter|routing|cumulativetodelta|groupbyattrs"}': true,
  '{__name__="type:opentelemetry_collector_extensions:sum",type=~"zpages|ballast|memorylimiter|jaegerremotesampling|healthcheck|pprof|oauth2clientauth|oidcauth|bearertokenauth|filestorage"}': true,
  '{__name__="type:opentelemetry_collector_connectors:sum",type=~"spanmetrics|forward"}': true,
  '{__name__="type:opentelemetry_collector_info:sum",type=~"deployment|daemonset|sidecar|statefulset"}': true,
  '{__name__="appsvcs:cores_by_product:sum"}': true,
  '{__name__="nto_custom_profiles:count"}': true,
  '{__name__="openshift_csi_share_configmap"}': true,
  '{__name__="openshift_csi_share_secret"}': true,
  '{__name__="openshift_csi_share_mount_failures_total"}': true,
  '{__name__="openshift_csi_share_mount_requests_total"}': true,
  '{__name__="eo_es_storage_info"}': true,
  '{__name__="eo_es_redundancy_policy_info"}': true,
  '{__name__="eo_es_defined_delete_namespaces_total"}': true,
  '{__name__="eo_es_misconfigured_memory_resources_info"}': true,
  '{__name__="cluster:eo_es_data_nodes_total:max"}': true,
  '{__name__="cluster:eo_es_documents_created_total:sum"}': true,
  '{__name__="cluster:eo_es_documents_deleted_total:sum"}': true,
  '{__name__="pod:eo_es_shards_total:max"}': true,
  '{__name__="eo_es_cluster_management_state_info"}': true,
  '{__name__="imageregistry:imagestreamtags_count:sum"}': true,
  '{__name__="imageregistry:operations_count:sum"}': true,
  '{__name__="log_logging_info"}': true,
  '{__name__="log_collector_error_count_total"}': true,
  '{__name__="log_forwarder_pipeline_info"}': true,
  '{__name__="log_forwarder_input_info"}': true,
  '{__name__="log_forwarder_output_info"}': true,
  '{__name__="cluster:log_collected_bytes_total:sum"}': true,
  '{__name__="cluster:log_logged_bytes_total:sum"}': true,
  '{__name__="openshift_logging:log_forwarder_pipelines:sum"}': true,
  '{__name__="openshift_logging:log_forwarders:sum"}': true,
  '{__name__="openshift_logging:log_forwarder_input_type:sum"}': true,
  '{__name__="openshift_logging:log_forwarder_output_type:sum"}': true,
  '{__name__="openshift_logging:vector_component_received_bytes_total:rate5m"}': true,
  '{__name__="cluster:kata_monitor_running_shim_count:sum"}': true,
  '{__name__="platform:hypershift_hostedclusters:max"}': true,
  '{__name__="platform:hypershift_nodepools:max"}': true,
  '{__name__="cluster_name:hypershift_nodepools_size:sum"}': true,
  '{__name__="cluster_name:hypershift_nodepools_available_replicas:sum"}': true,
  '{__name__="namespace:noobaa_unhealthy_bucket_claims:max"}': true,
  '{__name__="namespace:noobaa_buckets_claims:max"}': true,
  '{__name__="namespace:noobaa_unhealthy_namespace_resources:max"}': true,
  '{__name__="namespace:noobaa_namespace_resources:max"}': true,
  '{__name__="namespace:noobaa_unhealthy_namespace_buckets:max"}': true,
  '{__name__="namespace:noobaa_namespace_buckets:max"}': true,
  '{__name__="namespace:noobaa_accounts:max"}': true,
  '{__name__="namespace:noobaa_usage:max"}': true,
  '{__name__="namespace:noobaa_system_health_status:max"}': true,
  '{__name__="ocs_advanced_feature_usage"}': true,
  '{__name__="os_image_url_override:sum"}': true,
  '{__name__="cluster:mcd_nodes_with_unsupported_packages:count"}': true,
  '{__name__="cluster:mcd_total_unsupported_packages:sum"}': true,
  '{__name__="cluster:vsphere_topology_tags:max"}': true,
  '{__name__="cluster:vsphere_infrastructure_failure_domains:max"}': true,
  '{__name__="rhacs:telemetry:rox_central_info"}': true,
  '{__name__="rhacs:telemetry:rox_central_secured_clusters"}': true,
  '{__name__="rhacs:telemetry:rox_central_secured_nodes"}': true,
  '{__name__="rhacs:telemetry:rox_central_secured_vcpus"}': true,
  '{__name__="rhacs:telemetry:rox_sensor_info"}': true,
  '{__name__="ols:provider_model_configuration"}': true,
  '{__name__="ols:rest_api_query_calls_total:2xx"}': true,
  '{__name__="ols:rest_api_query_calls_total:4xx"}': true,
  '{__name__="ols:rest_api_query_calls_total:5xx"}': true,
  '{__name__="openshift:openshift_network_operator_ipsec_state:info"}': true,
  '{__name__="cluster:health:group_severity:count", severity=~"critical|warning|info|none"}': true,
  '{__name__="cluster:controlplane_topology:info", mode=~"HighlyAvailable|HighlyAvailableArbiter|SingleReplica|DualReplica|External"}': true,
  '{__name__="cluster:infrastructure_topology:info", mode=~"HighlyAvailable|SingleReplica"}': true,
  '{__name__="openshift:gateway_api_usage:count",gateway_class_type=~"openshift|not-openshift"}': true,
  '{__name__="cluster:mtv_migrations_status_total:sum", provider=~"ova|vsphere|openstack|openshift|ovirt|awsec2", target=~"Local|Remote", mode=~"Cold|Warm|RCM", status=~"Succeeded|Failed|Canceled"}': true,
  '{__name__="status:upgrading:version:rhoam_state:max"}': true,
};

// validateEntry does basic validation of an entry to ensure all required fields
// and their children are present, and have expected types.
local validateEntry(entry) =
  local validateMetadata =
    if !std.objectHas(entry, 'metadata') then
      error 'entry is missing metadata field'
    else if !std.isObject(entry.metadata) then
      error 'entry metadata field is not an object'
    else
      true;
  local validateOwners =
    if !std.objectHas(entry.metadata, 'owners') then
      error 'entry metadata is missing owners field'
    else if !std.isArray(entry.metadata.owners) then
      error 'entry metadata owners field is not an array'
    else if !std.all([std.isString(owner) for owner in entry.metadata.owners]) then
      error 'entry metadata owners field contains non-string values'
    else
      true;
  local validateDescription =
    if !std.objectHas(entry.metadata, 'description') then
      error 'entry metadata is missing description field'
    else if !std.isString(entry.metadata.description) then
      error 'entry metadata description field is not a string'
    else
      true;
  local validateLabelValues =
    if !std.objectHas(entry.metadata, 'label_values') then
      error 'entry metadata is missing label_values field'
    else if !std.isObject(entry.metadata.label_values) then
      error 'entry metadata label_values field is not an object'
    else if !std.all([std.isArray(entry.metadata.label_values[k]) for k in std.objectFields(entry.metadata.label_values)]) then
      error 'entry metadata label_values field contains non-array values'
    else if !std.all([std.all([std.isString(v) for v in entry.metadata.label_values[k]]) for k in std.objectFields(entry.metadata.label_values)]) then
      error 'entry metadata label_values field contains non-string array elements'
    else
      true;
  local validateConsumers =
    if !std.objectHas(entry.metadata, 'consumers') then
      error 'entry metadata is missing consumers field'
    else if !std.isArray(entry.metadata.consumers) then
      error 'entry metadata consumers field is not an array'
    else if !std.all([std.isString(consumer) for consumer in entry.metadata.consumers]) then
      error 'entry metadata consumers field contains non-string values'
    else
      true;
  local validateRule =
    if !std.objectHas(entry, 'rule') then
      error 'entry is missing rule field'
    else if !std.isString(entry.rule) then
      error 'entry rule field is not a string'
    else
      true;
  local validateMonitorMetricsMap =
    if !std.objectHas(entry, 'monitor_metrics') then
      error 'entry is missing monitor_metrics field'
    else if !std.isObject(entry.monitor_metrics) then
      error 'entry monitor_metrics field is not an object'
    else if !std.all([std.isArray(entry.monitor_metrics[k]) for k in std.objectFields(entry.monitor_metrics)]) then
      error 'entry monitor_metrics field contains non-array values'
    else if !std.all([std.all([std.isString(m) for m in entry.monitor_metrics[k]]) for k in std.objectFields(entry.monitor_metrics)]) then
      error 'entry monitor_metrics field contains non-string array elements'
    else
      local monitorKeys = std.objectFields(entry.monitor_metrics);
      local nonNamespacedNameNonEmptyKeys = std.filter(
        function(k)
          if k == '' then false
          else std.length(std.findSubstr('/', k)) != 1,
        monitorKeys,
      );
      if std.length(nonNamespacedNameNonEmptyKeys) > 0 then
        error 'entry monitor_metrics field contains invalid monitor keys (use namespacednames for monitor keys)'
      else if std.count(monitorKeys, '') > 0 && !std.objectHas(unknownMonitorIgnorelist, entry.rule) then
        error 'entry monitor_metrics field contains one or more empty monitor key(s)'
      else
        true;
  validateMetadata &&
  validateOwners &&
  validateDescription &&
  validateLabelValues &&
  validateConsumers &&
  validateRule &&
  validateMonitorMetricsMap;

local makeEntry(entry) =
  if validateEntry(entry) then entry else error 'validation failed';

local alertmanagerMonitorKey = 'openshift-monitoring/alertmanager-main-telemetry';
local clusterMonitoringOperatorMonitorKey = 'openshift-monitoring/cluster-monitoring-operator-telemetry';
local kubeStateMetricsMonitorKey = 'openshift-monitoring/kube-state-metrics-telemetry';
local kubeletMonitorKey = 'openshift-monitoring/kubelet-telemetry';
local nodeExporterMonitorKey = 'openshift-monitoring/node-exporter-telemetry';
local openshiftStateMetricsMonitorKey = 'openshift-monitoring/openshift-state-metrics-telemetry';
local prometheusK8sMonitorKey = 'openshift-monitoring/prometheus-k8s-telemetry';
local telemeterClientMonitorKey = 'openshift-monitoring/telemeter-client-telemetry';
local cmoMonitors = {
  [alertmanagerMonitorKey]: null,
  [clusterMonitoringOperatorMonitorKey]: null,
  [kubeStateMetricsMonitorKey]: null,
  [kubeletMonitorKey]: null,
  [nodeExporterMonitorKey]: null,
  [openshiftStateMetricsMonitorKey]: null,
  [prometheusK8sMonitorKey]: null,
  [telemeterClientMonitorKey]: null,
};

local entries = [
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring', '@smarterclayton'],
      description: 'cluster:cpu_usage_cores:sum is the current amount of CPU used by the whole cluster.',
      label_values: {},
      consumers: ['@openshift/openshift-team-olm', '@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:cpu_usage_cores:sum"}',
    monitor_metrics: {
      [kubeStateMetricsMonitorKey]: ['kube_pod_info'],
      [nodeExporterMonitorKey]: ['node_cpu_seconds_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'ALERTS metric contains all firing alerts with their severity levels.',
      label_values: {
        alertstate: ['firing'],
        severity: ['critical', 'warning', 'info', 'none'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="ALERTS",alertstate="firing",severity=~"critical|warning|info|none"}',
    monitor_metrics: {
      [prometheusK8sMonitorKey]: ['ALERTS'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'cluster:alertmanager_integrations:max tracks the number of alertmanager integrations configured.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:alertmanager_integrations:max"}',
    monitor_metrics: {
      [alertmanagerMonitorKey]: ['alertmanager_integrations'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'cluster:capacity_cpu_cores:sum is the total CPU capacity of the cluster in cores.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:capacity_cpu_cores:sum"}',
    monitor_metrics: {
      [kubeStateMetricsMonitorKey]: ['kube_node_status_capacity', 'kube_node_labels'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'cluster:capacity_memory_bytes:sum is the total memory capacity of the cluster in bytes.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:capacity_memory_bytes:sum"}',
    monitor_metrics: {
      [kubeStateMetricsMonitorKey]: ['kube_node_status_capacity', 'kube_node_labels'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'cluster:memory_usage_bytes:sum is the current amount of memory used by the whole cluster.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:memory_usage_bytes:sum"}',
    monitor_metrics: {
      [nodeExporterMonitorKey]: ['node_memory_MemTotal_bytes', 'node_memory_MemAvailable_bytes'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'cluster:node_instance_type_count:sum counts nodes by instance type, role, architecture, and OS.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:node_instance_type_count:sum"}',
    monitor_metrics: {
      [kubeStateMetricsMonitorKey]: ['kube_node_labels'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'cluster:telemetry_selected_series:count is the number of series selected for telemetry after filtering.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:telemetry_selected_series:count"}',
    monitor_metrics: {
      [telemeterClientMonitorKey]: ['federate_samples', 'federate_filtered_samples'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'cluster:virt_platform_nodes:sum counts nodes by virtualization platform type.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:virt_platform_nodes:sum"}',
    monitor_metrics: {
      [nodeExporterMonitorKey]: ['virt_platform'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'count:up0 counts the number of targets that are down.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="count:up0"}',
    monitor_metrics: {
      [prometheusK8sMonitorKey]: ['up'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'count:up1 counts the number of targets that are up.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="count:up1"}',
    monitor_metrics: {
      [prometheusK8sMonitorKey]: ['up'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'monitoring:container_memory_working_set_bytes:sum is the memory working set of monitoring stack containers.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="monitoring:container_memory_working_set_bytes:sum"}',
    monitor_metrics: {
      [kubeletMonitorKey]: ['container_memory_working_set_bytes'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'namespace_job:scrape_samples_post_metric_relabeling:topk3 tracks top 3 namespace/job pairs by scrape sample count after metric relabeling.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="namespace_job:scrape_samples_post_metric_relabeling:topk3"}',
    monitor_metrics: {
      [prometheusK8sMonitorKey]: ['scrape_samples_post_metric_relabeling'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'namespace_job:scrape_series_added:topk3_sum1h tracks top 3 namespace/job pairs by series added over 1 hour.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="namespace_job:scrape_series_added:topk3_sum1h"}',
    monitor_metrics: {
      [prometheusK8sMonitorKey]: ['scrape_series_added'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'node_role_os_version_machine:cpu_capacity_cores:sum aggregates CPU capacity by node role, OS, architecture, and hyperthread status.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="node_role_os_version_machine:cpu_capacity_cores:sum"}',
    monitor_metrics: {
      [kubeStateMetricsMonitorKey]: ['kube_node_labels'],
      [nodeExporterMonitorKey]: ['node_cpu_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'node_role_os_version_machine:cpu_capacity_sockets:sum aggregates CPU socket count by node role, OS, architecture, and hyperthread status.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="node_role_os_version_machine:cpu_capacity_sockets:sum"}',
    monitor_metrics: {
      [kubeStateMetricsMonitorKey]: ['kube_node_labels'],
      [nodeExporterMonitorKey]: ['node_cpu_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'openshift:cpu_usage_cores:sum is the current amount of CPU used by OpenShift infrastructure.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift:cpu_usage_cores:sum"}',
    monitor_metrics: {
      [nodeExporterMonitorKey]: ['node_cpu_seconds_total'],
      [kubeletMonitorKey]: ['container_cpu_usage_seconds_total'],
      [kubeStateMetricsMonitorKey]: ['kube_pod_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'openshift:memory_usage_bytes:sum is the current amount of memory used by OpenShift infrastructure.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift:memory_usage_bytes:sum"}',
    monitor_metrics: {
      [nodeExporterMonitorKey]: ['node_memory_MemTotal_bytes', 'node_memory_MemAvailable_bytes'],
      [kubeletMonitorKey]: ['container_memory_working_set_bytes'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'openshift:prometheus_tsdb_head_samples_appended_total:sum tracks the rate of samples appended to Prometheus TSDB.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift:prometheus_tsdb_head_samples_appended_total:sum"}',
    monitor_metrics: {
      [prometheusK8sMonitorKey]: ['prometheus_tsdb_head_samples_appended_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'openshift:prometheus_tsdb_head_series:sum tracks the total number of series in Prometheus TSDB head.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift:prometheus_tsdb_head_series:sum"}',
    monitor_metrics: {
      [prometheusK8sMonitorKey]: ['prometheus_tsdb_head_series'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'profile:cluster_monitoring_operator_collection_profile:max identifies the active monitoring collection profile.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="profile:cluster_monitoring_operator_collection_profile:max"}',
    monitor_metrics: {
      [clusterMonitoringOperatorMonitorKey]: ['cluster_monitoring_operator_collection_profile'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'vendor_model:node_accelerator_cards:sum counts accelerator cards by vendor and model.',
      label_values: {
        vendor: ['NVIDIA', 'AMD', 'GAUDI', 'INTEL', 'QUALCOMM', 'Marvell', 'Mellanox'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="vendor_model:node_accelerator_cards:sum",vendor=~"NVIDIA|AMD|GAUDI|INTEL|QUALCOMM|Marvell|Mellanox"}',
    monitor_metrics: {
      [nodeExporterMonitorKey]: ['node_accelerator_card_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'workload:cpu_usage_cores:sum is the current amount of CPU used by user workloads.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="workload:cpu_usage_cores:sum"}',
    monitor_metrics: {
      [kubeletMonitorKey]: ['container_cpu_usage_seconds_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'workload:memory_usage_bytes:sum is the current amount of memory used by user workloads.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="workload:memory_usage_bytes:sum"}',
    monitor_metrics: {
      [kubeletMonitorKey]: ['container_memory_working_set_bytes'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'cluster:usage:.* captures various cluster usage metrics for capacity planning and telemetry.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__=~"cluster:usage:.*"}',
    monitor_metrics: {
      [kubeStateMetricsMonitorKey]: ['kube_node_labels', 'kube_node_spec_unschedulable', 'kube_node_status_condition', 'kube_pod_restart_policy', 'kube_running_pod_ready'],
      [kubeletMonitorKey]: ['apiserver_storage_objects', 'kubelet_containers_per_pod_count_sum'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'monitoring:haproxy_server_http_responses_total:sum tracks HTTP response codes from monitoring stack HAProxy.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="monitoring:haproxy_server_http_responses_total:sum"}',
    monitor_metrics: {
      '': ['haproxy_server_http_responses_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cluster-lifecycle'],
      description: 'cluster_version reports the cluster version information.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster_version"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cluster-lifecycle'],
      description: 'cluster_version_available_updates reports available cluster updates.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster_version_available_updates"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cluster-lifecycle'],
      description: 'cluster_version_capability reports enabled cluster capabilities.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster_version_capability"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cluster-lifecycle'],
      description: 'cluster_operator_up reports whether cluster operators are running.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster_operator_up"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cluster-lifecycle'],
      description: 'cluster_operator_conditions reports cluster operator condition status.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster_operator_conditions"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cluster-lifecycle'],
      description: 'cluster_version_payload reports the cluster version payload information.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster_version_payload"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cluster-lifecycle'],
      description: 'cluster_installer reports the installer used to deploy the cluster.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster_installer"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cluster-lifecycle'],
      description: 'cluster_infrastructure_provider reports the infrastructure provider for the cluster.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster_infrastructure_provider"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cluster-lifecycle'],
      description: 'cluster_feature_set reports the enabled feature set for the cluster.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster_feature_set"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-etcd'],
      description: 'instance:etcd_object_counts:sum reports the number of objects stored in etcd.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="instance:etcd_object_counts:sum"}',
    monitor_metrics: {
      [kubeletMonitorKey]: ['apiserver_storage_objects'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-apiserver'],
      description: 'code:apiserver_request_total:rate:sum tracks API server request rates by HTTP status code.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="code:apiserver_request_total:rate:sum"}',
    monitor_metrics: {
      [kubeletMonitorKey]: ['apiserver_request_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-virtualization'],
      description: 'cnv:vmi_status_running:count counts running virtual machine instances.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cnv:vmi_status_running:count"}',
    monitor_metrics: {
      '': ['kubevirt_vmi_phase_count'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-virtualization'],
      description: 'cnv_abnormal reports abnormal memory conditions for virtual machines.',
      label_values: {
        reason: ['memory_working_set_delta_from_request', 'memory_rss_delta_from_request'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cnv_abnormal", reason=~"memory_working_set_delta_from_request|memory_rss_delta_from_request"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-virtualization'],
      description: 'cluster:vmi_request_cpu_cores:sum reports total CPU requested by virtual machines.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:vmi_request_cpu_cores:sum"}',
    monitor_metrics: {
      [kubeStateMetricsMonitorKey]: ['kube_pod_container_resource_requests', 'kube_pod_status_phase', 'kube_pod_labels'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-olm'],
      description: 'subscription_sync_total reports the number of operator subscription syncs.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="subscription_sync_total"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-olm'],
      description: 'olm_resolution_duration_seconds reports OLM dependency resolution duration.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="olm_resolution_duration_seconds"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-olm'],
      description: 'csv_succeeded reports successful CSV installations.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="csv_succeeded"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-olm'],
      description: 'csv_abnormal reports abnormal CSV states.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="csv_abnormal"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-storage'],
      description: 'cluster:kube_persistentvolumeclaim_resource_requests_storage_bytes:provisioner:sum aggregates PVC storage requests by provisioner.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:kube_persistentvolumeclaim_resource_requests_storage_bytes:provisioner:sum"}',
    monitor_metrics: {
      [kubeStateMetricsMonitorKey]: ['kube_persistentvolumeclaim_resource_requests_storage_bytes', 'kube_persistentvolumeclaim_info', 'kube_storageclass_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-storage'],
      description: 'cluster:kubelet_volume_stats_used_bytes:provisioner:sum aggregates volume usage by provisioner.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:kubelet_volume_stats_used_bytes:provisioner:sum"}',
    monitor_metrics: {
      [kubeletMonitorKey]: ['kubelet_volume_stats_used_bytes'],
      [kubeStateMetricsMonitorKey]: ['kube_persistentvolumeclaim_info', 'kube_storageclass_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'ceph_cluster_total_bytes reports total Ceph cluster capacity.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="ceph_cluster_total_bytes"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'ceph_cluster_total_used_raw_bytes reports raw storage used in Ceph cluster.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="ceph_cluster_total_used_raw_bytes"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'ceph_health_status reports Ceph cluster health status.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="ceph_health_status"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'odf_system_raw_capacity_total_bytes reports total ODF system raw capacity.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="odf_system_raw_capacity_total_bytes"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'odf_system_raw_capacity_used_bytes reports used ODF system raw capacity.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="odf_system_raw_capacity_used_bytes"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'odf_system_health_status reports ODF system health status.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="odf_system_health_status"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'job:ceph_osd_metadata:count counts Ceph OSD instances.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="job:ceph_osd_metadata:count"}',
    monitor_metrics: {
      '': ['ceph_osd_metadata'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'job:kube_pv:count counts persistent volumes.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="job:kube_pv:count"}',
    monitor_metrics: {
      [kubeStateMetricsMonitorKey]: ['kube_persistentvolume_info', 'kube_storageclass_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'job:odf_system_pvs:count counts ODF system persistent volumes.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="job:odf_system_pvs:count"}',
    monitor_metrics: {
      [kubeStateMetricsMonitorKey]: ['kube_persistentvolume_info', 'kube_storageclass_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'job:ceph_pools_iops:total reports total IOPS across Ceph pools.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="job:ceph_pools_iops:total"}',
    monitor_metrics: {
      '': ['ceph_pool_rd', 'ceph_pool_wr'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'job:ceph_pools_iops_bytes:total reports total IOPS bytes across Ceph pools.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="job:ceph_pools_iops_bytes:total"}',
    monitor_metrics: {
      '': ['ceph_pool_rd_bytes', 'ceph_pool_wr_bytes'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'job:ceph_versions_running:count counts running Ceph component versions.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="job:ceph_versions_running:count"}',
    monitor_metrics: {
      '': ['ceph_mon_metadata', 'ceph_osd_metadata', 'ceph_rgw_metadata', 'ceph_mds_metadata'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'job:noobaa_total_unhealthy_buckets:sum counts total unhealthy NooBaa buckets.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="job:noobaa_total_unhealthy_buckets:sum"}',
    monitor_metrics: {
      '': ['NooBaa_num_unhealthy_buckets', 'NooBaa_num_unhealthy_bucket_claims'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'job:noobaa_bucket_count:sum counts total NooBaa buckets.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="job:noobaa_bucket_count:sum"}',
    monitor_metrics: {
      '': ['NooBaa_num_buckets', 'NooBaa_num_buckets_claims'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'job:noobaa_total_object_count:sum counts total NooBaa objects.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="job:noobaa_total_object_count:sum"}',
    monitor_metrics: {
      '': ['NooBaa_num_objects', 'NooBaa_num_objects_buckets_claims'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'odf_system_bucket_count reports ODF system bucket count for OCS.',
      label_values: {
        system_type: ['OCS'],
        system_vendor: ['Red Hat'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="odf_system_bucket_count", system_type="OCS", system_vendor="Red Hat"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'odf_system_objects_total reports total objects in ODF system for OCS.',
      label_values: {
        system_type: ['OCS'],
        system_vendor: ['Red Hat'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="odf_system_objects_total", system_type="OCS", system_vendor="Red Hat"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'noobaa_accounts_num reports number of NooBaa accounts.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="noobaa_accounts_num"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'noobaa_total_usage reports total NooBaa storage usage.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="noobaa_total_usage"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-console'],
      description: 'console_url reports the console URL.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="console_url"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-console'],
      description: 'cluster:console_auth_login_requests_total:sum reports total console login requests.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:console_auth_login_requests_total:sum"}',
    monitor_metrics: {
      '': ['console_auth_login_requests_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-console'],
      description: 'cluster:console_auth_login_successes_total:sum reports total successful console logins.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:console_auth_login_successes_total:sum"}',
    monitor_metrics: {
      '': ['console_auth_login_successes_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-console'],
      description: 'cluster:console_auth_login_failures_total:sum reports total failed console logins.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:console_auth_login_failures_total:sum"}',
    monitor_metrics: {
      '': ['console_auth_login_failures_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-console'],
      description: 'cluster:console_auth_logout_requests_total:sum reports total console logout requests.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:console_auth_logout_requests_total:sum"}',
    monitor_metrics: {
      '': ['console_auth_logout_requests_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-console'],
      description: 'cluster:console_usage_users:max reports maximum active console users.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:console_usage_users:max"}',
    monitor_metrics: {
      '': ['console_usage_users'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-console'],
      description: 'cluster:console_plugins_info:max reports console plugin information.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:console_plugins_info:max"}',
    monitor_metrics: {
      '': ['console_plugins_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-console'],
      description: 'cluster:console_customization_perspectives_info:max reports console customization perspective info.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:console_customization_perspectives_info:max"}',
    monitor_metrics: {
      '': ['console_customization_perspectives_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-networking'],
      description: 'cluster:ovnkube_controller_egress_routing_via_host:max reports egress routing via host.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:ovnkube_controller_egress_routing_via_host:max"}',
    monitor_metrics: {
      '': ['ovnkube_controller_egress_routing_via_host'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-networking'],
      description: 'cluster:ovnkube_controller_admin_network_policies_db_objects:max reports admin network policies database objects.',
      label_values: {
        table_name: ['ACL', 'Address_Set'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:ovnkube_controller_admin_network_policies_db_objects:max",table_name=~"ACL|Address_Set"}',
    monitor_metrics: {
      '': ['ovnkube_controller_admin_network_policies_db_objects'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-networking'],
      description: 'cluster:ovnkube_controller_baseline_admin_network_policies_db_objects:max reports baseline admin network policies database objects.',
      label_values: {
        table_name: ['ACL', 'Address_Set'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:ovnkube_controller_baseline_admin_network_policies_db_objects:max",table_name=~"ACL|Address_Set"}',
    monitor_metrics: {
      '': ['ovnkube_controller_baseline_admin_network_policies_db_objects'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-networking'],
      description: 'cluster:ovnkube_controller_admin_network_policies_rules:max reports admin network policies rules.',
      label_values: {
        direction: ['Ingress', 'Egress'],
        action: ['Pass', 'Allow', 'Deny'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:ovnkube_controller_admin_network_policies_rules:max",direction=~"Ingress|Egress",action=~"Pass|Allow|Deny"}',
    monitor_metrics: {
      '': ['ovnkube_controller_admin_network_policies_rules'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-networking'],
      description: 'cluster:ovnkube_controller_baseline_admin_network_policies_rules:max reports baseline admin network policies rules.',
      label_values: {
        direction: ['Ingress', 'Egress'],
        action: ['Allow', 'Deny'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:ovnkube_controller_baseline_admin_network_policies_rules:max",direction=~"Ingress|Egress",action=~"Allow|Deny"}',
    monitor_metrics: {
      '': ['ovnkube_controller_baseline_admin_network_policies_rules'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-networking'],
      description: 'cluster:network_attachment_definition_instances:max reports network attachment definition instances.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:network_attachment_definition_instances:max"}',
    monitor_metrics: {
      '': ['network_attachment_definition_instances'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-networking'],
      description: 'cluster:network_attachment_definition_enabled_instance_up:max reports enabled network attachment definition instances that are up.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:network_attachment_definition_enabled_instance_up:max"}',
    monitor_metrics: {
      '': ['network_attachment_definition_enabled_instance_up'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-networking'],
      description: 'cluster:ingress_controller_aws_nlb_active:sum reports active AWS NLB ingress controllers.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:ingress_controller_aws_nlb_active:sum"}',
    monitor_metrics: {
      '': ['ingress_controller_aws_nlb_active'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-networking'],
      description: 'cluster:route_metrics_controller_routes_per_shard:min reports minimum routes per shard.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:route_metrics_controller_routes_per_shard:min"}',
    monitor_metrics: {
      '': ['route_metrics_controller_routes_per_shard'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-networking'],
      description: 'cluster:route_metrics_controller_routes_per_shard:max reports maximum routes per shard.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:route_metrics_controller_routes_per_shard:max"}',
    monitor_metrics: {
      '': ['route_metrics_controller_routes_per_shard'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-networking'],
      description: 'cluster:route_metrics_controller_routes_per_shard:avg reports average routes per shard.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:route_metrics_controller_routes_per_shard:avg"}',
    monitor_metrics: {
      '': ['route_metrics_controller_routes_per_shard'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-networking'],
      description: 'cluster:route_metrics_controller_routes_per_shard:median reports median routes per shard.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:route_metrics_controller_routes_per_shard:median"}',
    monitor_metrics: {
      '': ['route_metrics_controller_routes_per_shard'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-networking'],
      description: 'cluster:openshift_route_info:tls_termination:sum aggregates route info by TLS termination type.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:openshift_route_info:tls_termination:sum"}',
    monitor_metrics: {
      [openshiftStateMetricsMonitorKey]: ['openshift_route_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cluster-observability'],
      description: 'insightsclient_request_send_total reports total insights client requests sent.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="insightsclient_request_send_total"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-migration'],
      description: 'cam_app_workload_migrations reports application workload migrations.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cam_app_workload_migrations"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-apiserver'],
      description: 'cluster:apiserver_current_inflight_requests:sum:max_over_time:2m reports maximum inflight API server requests over 2 minutes.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:apiserver_current_inflight_requests:sum:max_over_time:2m"}',
    monitor_metrics: {
      [kubeletMonitorKey]: ['apiserver_current_inflight_requests'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['https://github.com/integr8ly'],
      description: 'rhmi_status reports RHMI installation status.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="rhmi_status"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['https://github.com/integr8ly', '@boomatang'],
      description: 'state:rhoam_critical_alerts:max reports maximum critical RHOAM alerts.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="state:rhoam_critical_alerts:max"}',
    monitor_metrics: {
      '': ['rhoam_critical_alerts'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['https://github.com/integr8ly', '@boomatang'],
      description: 'state:rhoam_warning_alerts:max reports maximum warning RHOAM alerts.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="state:rhoam_warning_alerts:max"}',
    monitor_metrics: {
      '': ['rhoam_warning_alerts'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['https://github.com/integr8ly', '@boomatang'],
      description: 'rhoam_7d_slo_percentile:max reports RHOAM 7-day SLO percentile.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="rhoam_7d_slo_percentile:max"}',
    monitor_metrics: {
      '': ['rhoam_7d_slo_percentile'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['https://github.com/integr8ly', '@boomatang'],
      description: 'rhoam_7d_slo_remaining_error_budget:max reports RHOAM 7-day remaining error budget.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="rhoam_7d_slo_remaining_error_budget:max"}',
    monitor_metrics: {
      '': ['rhoam_7d_slo_remaining_error_budget'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cluster-lifecycle'],
      description: 'cluster_legacy_scheduler_policy reports whether legacy scheduler policy is configured.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster_legacy_scheduler_policy"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cluster-lifecycle'],
      description: 'cluster_master_schedulable reports whether master nodes are schedulable.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster_master_schedulable"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-devtools'],
      description: 'che_workspace_status reports Che workspace status.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="che_workspace_status"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-devtools'],
      description: 'che_workspace_started_total reports total Che workspaces started.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="che_workspace_started_total"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-devtools'],
      description: 'che_workspace_failure_total reports total Che workspace failures.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="che_workspace_failure_total"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-devtools'],
      description: 'che_workspace_start_time_seconds_sum reports sum of Che workspace start times.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="che_workspace_start_time_seconds_sum"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-devtools'],
      description: 'che_workspace_start_time_seconds_count reports count of Che workspace starts.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="che_workspace_start_time_seconds_count"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cloud-credential-operator'],
      description: 'cco_credentials_mode reports CCO credentials mode.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cco_credentials_mode"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-storage'],
      description: 'cluster:kube_persistentvolume_plugin_type_counts:sum counts persistent volumes by plugin type.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:kube_persistentvolume_plugin_type_counts:sum"}',
    monitor_metrics: {
      [kubeletMonitorKey]: ['pv_collector_total_pv_count'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-acm'],
      description: 'acm_managed_cluster_info reports ACM managed cluster information.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="acm_managed_cluster_info"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-acm'],
      description: 'acm_managed_cluster_worker_cores:max reports maximum worker cores in ACM managed clusters.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="acm_managed_cluster_worker_cores:max"}',
    monitor_metrics: {
      '': ['acm_managed_cluster_worker_cores'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-acm'],
      description: 'acm_console_page_count:sum counts ACM console page views by page type.',
      label_values: {
        page: ['overview-classic', 'overview-fleet', 'search', 'search-details', 'clusters', 'application', 'governance'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="acm_console_page_count:sum", page=~"overview-classic|overview-fleet|search|search-details|clusters|application|governance"}',
    monitor_metrics: {
      '': ['acm_console_page_count'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-vsphere'],
      description: 'cluster:vsphere_vcenter_info:sum reports vSphere vCenter information.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:vsphere_vcenter_info:sum"}',
    monitor_metrics: {
      '': ['vsphere_vcenter_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-vsphere'],
      description: 'cluster:vsphere_esxi_version_total:sum reports vSphere ESXi version counts.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:vsphere_esxi_version_total:sum"}',
    monitor_metrics: {
      '': ['vsphere_esxi_version_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-vsphere'],
      description: 'cluster:vsphere_node_hw_version_total:sum reports vSphere node hardware version counts.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:vsphere_node_hw_version_total:sum"}',
    monitor_metrics: {
      '': ['vsphere_node_hw_version_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-builds'],
      description: 'openshift:build_by_strategy:sum aggregates builds by strategy.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift:build_by_strategy:sum"}',
    monitor_metrics: {
      [openshiftStateMetricsMonitorKey]: ['openshift_build_status_phase_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-data-science'],
      description: 'rhods_aggregate_availability reports RHODS aggregate availability.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="rhods_aggregate_availability"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-data-science'],
      description: 'rhods_total_users reports total RHODS users.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="rhods_total_users"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-etcd'],
      description: 'instance:etcd_disk_wal_fsync_duration_seconds:histogram_quantile reports etcd WAL fsync duration 99th percentile.',
      label_values: {
        quantile: ['0.99'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="instance:etcd_disk_wal_fsync_duration_seconds:histogram_quantile",quantile="0.99"}',
    monitor_metrics: {
      '': ['etcd_disk_wal_fsync_duration_seconds_bucket'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-etcd'],
      description: 'instance:etcd_mvcc_db_total_size_in_bytes:sum reports total etcd database size.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="instance:etcd_mvcc_db_total_size_in_bytes:sum"}',
    monitor_metrics: {
      '': ['etcd_mvcc_db_total_size_in_bytes'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-etcd'],
      description: 'instance:etcd_network_peer_round_trip_time_seconds:histogram_quantile reports etcd network peer RTT 99th percentile.',
      label_values: {
        quantile: ['0.99'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="instance:etcd_network_peer_round_trip_time_seconds:histogram_quantile",quantile="0.99"}',
    monitor_metrics: {
      '': ['etcd_network_peer_round_trip_time_seconds_bucket'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-etcd'],
      description: 'instance:etcd_mvcc_db_total_size_in_use_in_bytes:sum reports etcd database size in use.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="instance:etcd_mvcc_db_total_size_in_use_in_bytes:sum"}',
    monitor_metrics: {
      '': ['etcd_mvcc_db_total_size_in_use_in_bytes'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-etcd'],
      description: 'instance:etcd_disk_backend_commit_duration_seconds:histogram_quantile reports etcd backend commit duration 99th percentile.',
      label_values: {
        quantile: ['0.99'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="instance:etcd_disk_backend_commit_duration_seconds:histogram_quantile",quantile="0.99"}',
    monitor_metrics: {
      '': ['etcd_disk_backend_commit_duration_seconds_bucket'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-observability'],
      description: 'jaeger_operator_instances_storage_types reports Jaeger operator instance storage types.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="jaeger_operator_instances_storage_types"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-observability'],
      description: 'jaeger_operator_instances_strategies reports Jaeger operator instance strategies.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="jaeger_operator_instances_strategies"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-observability'],
      description: 'jaeger_operator_instances_agent_strategies reports Jaeger operator instance agent strategies.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="jaeger_operator_instances_agent_strategies"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-observability'],
      description: 'type:tempo_operator_tempostack_storage_backend:sum reports Tempo operator storage backend types.',
      label_values: {
        type: ['azure', 'gcs', 's3'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="type:tempo_operator_tempostack_storage_backend:sum",type=~"azure|gcs|s3"}',
    monitor_metrics: {
      '': ['tempo_operator_tempostack_storage_backend'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-observability'],
      description: 'state:tempo_operator_tempostack_managed:sum reports Tempo operator managed state.',
      label_values: {
        state: ['Managed', 'Unmanaged'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="state:tempo_operator_tempostack_managed:sum",state=~"Managed|Unmanaged"}',
    monitor_metrics: {
      '': ['tempo_operator_tempostack_managed'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-observability'],
      description: 'type:tempo_operator_tempostack_multi_tenancy:sum reports Tempo operator multi-tenancy types.',
      label_values: {
        type: ['static', 'openshift', 'disabled'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="type:tempo_operator_tempostack_multi_tenancy:sum",type=~"static|openshift|disabled"}',
    monitor_metrics: {
      '': ['tempo_operator_tempostack_multi_tenancy'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-observability'],
      description: 'enabled:tempo_operator_tempostack_jaeger_ui:sum reports Tempo operator Jaeger UI enabled status.',
      label_values: {
        enabled: ['true', 'false'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="enabled:tempo_operator_tempostack_jaeger_ui:sum",enabled=~"true|false"}',
    monitor_metrics: {
      '': ['tempo_operator_tempostack_jaeger_ui'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-observability'],
      description: 'type:opentelemetry_collector_receivers:sum reports OpenTelemetry collector receiver types.',
      label_values: {
        type: ['jaeger', 'hostmetrics', 'opencensus', 'prometheus', 'zipkin', 'kafka', 'filelog', 'journald', 'k8sevents', 'kubeletstats', 'k8scluster', 'k8sobjects', 'otlp'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="type:opentelemetry_collector_receivers:sum",type=~"jaeger|hostmetrics|opencensus|prometheus|zipkin|kafka|filelog|journald|k8sevents|kubeletstats|k8scluster|k8sobjects|otlp"}',
    monitor_metrics: {
      '': ['opentelemetry_collector_receivers'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-observability'],
      description: 'type:opentelemetry_collector_exporters:sum reports OpenTelemetry collector exporter types.',
      label_values: {
        type: ['debug', 'logging', 'otlp', 'otlphttp', 'prometheus', 'lokiexporter', 'kafka', 'awscloudwatchlogs', 'loadbalancing'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="type:opentelemetry_collector_exporters:sum",type=~"debug|logging|otlp|otlphttp|prometheus|lokiexporter|kafka|awscloudwatchlogs|loadbalancing"}',
    monitor_metrics: {
      '': ['opentelemetry_collector_exporters'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-observability'],
      description: 'type:opentelemetry_collector_processors:sum reports OpenTelemetry collector processor types.',
      label_values: {
        type: ['batch', 'memorylimiter', 'attributes', 'resource', 'span', 'k8sattributes', 'resourcedetection', 'filter', 'routing', 'cumulativetodelta', 'groupbyattrs'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="type:opentelemetry_collector_processors:sum",type=~"batch|memorylimiter|attributes|resource|span|k8sattributes|resourcedetection|filter|routing|cumulativetodelta|groupbyattrs"}',
    monitor_metrics: {
      '': ['opentelemetry_collector_processors'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-observability'],
      description: 'type:opentelemetry_collector_extensions:sum reports OpenTelemetry collector extension types.',
      label_values: {
        type: ['zpages', 'ballast', 'memorylimiter', 'jaegerremotesampling', 'healthcheck', 'pprof', 'oauth2clientauth', 'oidcauth', 'bearertokenauth', 'filestorage'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="type:opentelemetry_collector_extensions:sum",type=~"zpages|ballast|memorylimiter|jaegerremotesampling|healthcheck|pprof|oauth2clientauth|oidcauth|bearertokenauth|filestorage"}',
    monitor_metrics: {
      '': ['opentelemetry_collector_extensions'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-observability'],
      description: 'type:opentelemetry_collector_connectors:sum reports OpenTelemetry collector connector types.',
      label_values: {
        type: ['spanmetrics', 'forward'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="type:opentelemetry_collector_connectors:sum",type=~"spanmetrics|forward"}',
    monitor_metrics: {
      '': ['opentelemetry_collector_connectors'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-observability'],
      description: 'type:opentelemetry_collector_info:sum reports OpenTelemetry collector deployment types.',
      label_values: {
        type: ['deployment', 'daemonset', 'sidecar', 'statefulset'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="type:opentelemetry_collector_info:sum",type=~"deployment|daemonset|sidecar|statefulset"}',
    monitor_metrics: {
      '': ['opentelemetry_collector_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-app-services'],
      description: 'appsvcs:cores_by_product:sum reports application services CPU cores by product.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="appsvcs:cores_by_product:sum"}',
    monitor_metrics: {
      '': ['appsvcs_cpu_usage_cores'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-node-tuning-operator'],
      description: 'nto_custom_profiles:count counts custom Node Tuning Operator profiles.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="nto_custom_profiles:count"}',
    monitor_metrics: {
      '': ['nto_profile_calculated_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-storage'],
      description: 'openshift_csi_share_configmap reports CSI share configmap usage.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift_csi_share_configmap"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-storage'],
      description: 'openshift_csi_share_secret reports CSI share secret usage.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift_csi_share_secret"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-storage'],
      description: 'openshift_csi_share_mount_failures_total reports total CSI share mount failures.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift_csi_share_mount_failures_total"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-storage'],
      description: 'openshift_csi_share_mount_requests_total reports total CSI share mount requests.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift_csi_share_mount_requests_total"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'eo_es_storage_info reports Elasticsearch storage information.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="eo_es_storage_info"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'eo_es_redundancy_policy_info reports Elasticsearch redundancy policy information.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="eo_es_redundancy_policy_info"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'eo_es_defined_delete_namespaces_total reports total defined delete namespaces in Elasticsearch.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="eo_es_defined_delete_namespaces_total"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'eo_es_misconfigured_memory_resources_info reports Elasticsearch misconfigured memory resources.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="eo_es_misconfigured_memory_resources_info"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'cluster:eo_es_data_nodes_total:max reports maximum Elasticsearch data nodes.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:eo_es_data_nodes_total:max"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'cluster:eo_es_documents_created_total:sum reports total Elasticsearch documents created.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:eo_es_documents_created_total:sum"}',
    monitor_metrics: {
      '': ['es_indices_doc_number'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'cluster:eo_es_documents_deleted_total:sum reports total Elasticsearch documents deleted.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:eo_es_documents_deleted_total:sum"}',
    monitor_metrics: {
      '': ['es_indices_doc_deleted_number'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'pod:eo_es_shards_total:max reports maximum Elasticsearch shards per pod.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="pod:eo_es_shards_total:max"}',
    monitor_metrics: {
      '': ['es_cluster_shards_number'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'eo_es_cluster_management_state_info reports Elasticsearch cluster management state.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="eo_es_cluster_management_state_info"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-image-registry'],
      description: 'imageregistry:imagestreamtags_count:sum reports total image stream tags.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="imageregistry:imagestreamtags_count:sum"}',
    monitor_metrics: {
      '': ['image_registry_image_stream_tags_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-image-registry'],
      description: 'imageregistry:operations_count:sum reports total image registry operations.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="imageregistry:operations_count:sum"}',
    monitor_metrics: {
      '': ['imageregistry_request_duration_seconds_count'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'log_logging_info reports logging configuration information.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="log_logging_info"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'log_collector_error_count_total reports total log collector errors.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="log_collector_error_count_total"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'log_forwarder_pipeline_info reports log forwarder pipeline information.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="log_forwarder_pipeline_info"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'log_forwarder_input_info reports log forwarder input information.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="log_forwarder_input_info"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'log_forwarder_output_info reports log forwarder output information.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="log_forwarder_output_info"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'cluster:log_collected_bytes_total:sum reports total bytes collected by logging.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:log_collected_bytes_total:sum"}',
    monitor_metrics: {
      '': ['log_collected_bytes_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'cluster:log_logged_bytes_total:sum reports total bytes logged.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:log_logged_bytes_total:sum"}',
    monitor_metrics: {
      '': ['log_logged_bytes_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'openshift_logging:log_forwarder_pipelines:sum reports total log forwarder pipelines.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift_logging:log_forwarder_pipelines:sum"}',
    monitor_metrics: {
      '': ['log_forwarder_pipelines'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'openshift_logging:log_forwarders:sum reports total log forwarders.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift_logging:log_forwarders:sum"}',
    monitor_metrics: {
      '': ['log_forwarder_pipelines'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'openshift_logging:log_forwarder_input_type:sum aggregates log forwarder inputs by type.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift_logging:log_forwarder_input_type:sum"}',
    monitor_metrics: {
      '': ['log_forwarder_input_type'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'openshift_logging:log_forwarder_output_type:sum aggregates log forwarder outputs by type.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift_logging:log_forwarder_output_type:sum"}',
    monitor_metrics: {
      '': ['log_forwarder_output_type'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-logging'],
      description: 'openshift_logging:vector_component_received_bytes_total:rate5m reports Vector component received bytes rate.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift_logging:vector_component_received_bytes_total:rate5m"}',
    monitor_metrics: {
      '': ['vector_component_received_bytes_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-sandboxed-containers'],
      description: 'cluster:kata_monitor_running_shim_count:sum reports total running Kata shims.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:kata_monitor_running_shim_count:sum"}',
    monitor_metrics: {
      '': ['kata_monitor_running_shim_count'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-hypershift'],
      description: 'platform:hypershift_hostedclusters:max reports maximum HyperShift hosted clusters.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="platform:hypershift_hostedclusters:max"}',
    monitor_metrics: {
      '': ['hypershift_hostedclusters'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-hypershift'],
      description: 'platform:hypershift_nodepools:max reports maximum HyperShift node pools.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="platform:hypershift_nodepools:max"}',
    monitor_metrics: {
      '': ['hypershift_nodepools'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-hypershift'],
      description: 'cluster_name:hypershift_nodepools_size:sum reports HyperShift node pool size by cluster.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster_name:hypershift_nodepools_size:sum"}',
    monitor_metrics: {
      '': ['hypershift_nodepools_size'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-hypershift'],
      description: 'cluster_name:hypershift_nodepools_available_replicas:sum reports HyperShift node pool available replicas by cluster.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster_name:hypershift_nodepools_available_replicas:sum"}',
    monitor_metrics: {
      '': ['hypershift_nodepools_available_replicas'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'namespace:noobaa_unhealthy_bucket_claims:max reports maximum unhealthy NooBaa bucket claims by namespace.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="namespace:noobaa_unhealthy_bucket_claims:max"}',
    monitor_metrics: {
      '': ['NooBaa_num_unhealthy_bucket_claims'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'namespace:noobaa_buckets_claims:max reports maximum NooBaa bucket claims by namespace.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="namespace:noobaa_buckets_claims:max"}',
    monitor_metrics: {
      '': ['NooBaa_num_buckets_claims'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'namespace:noobaa_unhealthy_namespace_resources:max reports maximum unhealthy NooBaa namespace resources by namespace.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="namespace:noobaa_unhealthy_namespace_resources:max"}',
    monitor_metrics: {
      '': ['NooBaa_num_unhealthy_namespace_resources'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'namespace:noobaa_namespace_resources:max reports maximum NooBaa namespace resources by namespace.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="namespace:noobaa_namespace_resources:max"}',
    monitor_metrics: {
      '': ['NooBaa_num_namespace_resources'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'namespace:noobaa_unhealthy_namespace_buckets:max reports maximum unhealthy NooBaa namespace buckets by namespace.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="namespace:noobaa_unhealthy_namespace_buckets:max"}',
    monitor_metrics: {
      '': ['NooBaa_num_unhealthy_namespace_buckets'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'namespace:noobaa_namespace_buckets:max reports maximum NooBaa namespace buckets by namespace.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="namespace:noobaa_namespace_buckets:max"}',
    monitor_metrics: {
      '': ['NooBaa_num_namespace_buckets'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'namespace:noobaa_accounts:max reports maximum NooBaa accounts by namespace.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="namespace:noobaa_accounts:max"}',
    monitor_metrics: {
      '': ['NooBaa_accounts_num'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'namespace:noobaa_usage:max reports maximum NooBaa usage by namespace.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="namespace:noobaa_usage:max"}',
    monitor_metrics: {
      '': ['NooBaa_total_usage'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'namespace:noobaa_system_health_status:max reports NooBaa system health status by namespace.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="namespace:noobaa_system_health_status:max"}',
    monitor_metrics: {
      '': ['NooBaa_odf_health_status'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-ocs'],
      description: 'ocs_advanced_feature_usage reports OCS advanced feature usage.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="ocs_advanced_feature_usage"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-machine-config-operator'],
      description: 'os_image_url_override:sum reports OS image URL override usage.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="os_image_url_override:sum"}',
    monitor_metrics: {
      '': ['os_image_url_override'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-machine-config-operator'],
      description: 'cluster:mcd_nodes_with_unsupported_packages:count counts nodes with unsupported packages.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:mcd_nodes_with_unsupported_packages:count"}',
    monitor_metrics: {
      '': ['mcd_local_unsupported_packages'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-machine-config-operator'],
      description: 'cluster:mcd_total_unsupported_packages:sum reports total unsupported packages across all nodes.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:mcd_total_unsupported_packages:sum"}',
    monitor_metrics: {
      '': ['mcd_local_unsupported_packages'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-vsphere'],
      description: 'cluster:vsphere_topology_tags:max reports vSphere topology tags usage.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:vsphere_topology_tags:max"}',
    monitor_metrics: {
      '': ['vsphere_topology_tags'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-vsphere'],
      description: 'cluster:vsphere_infrastructure_failure_domains:max reports vSphere infrastructure failure domains.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:vsphere_infrastructure_failure_domains:max"}',
    monitor_metrics: {
      '': ['vsphere_infrastructure_failure_domains'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-apiserver'],
      description: 'apiserver_list_watch_request_success_total:rate:sum reports API server list/watch request success rate.',
      label_values: {
        verb: ['LIST', 'WATCH'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="apiserver_list_watch_request_success_total:rate:sum", verb=~"LIST|WATCH"}',
    monitor_metrics: {
      [kubeletMonitorKey]: ['apiserver_request_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-acs'],
      description: 'rhacs:telemetry:rox_central_info reports RHACS central information.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="rhacs:telemetry:rox_central_info"}',
    monitor_metrics: {
      '': ['rox_central_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-acs'],
      description: 'rhacs:telemetry:rox_central_secured_clusters reports RHACS secured cluster count.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="rhacs:telemetry:rox_central_secured_clusters"}',
    monitor_metrics: {
      '': ['rox_central_secured_clusters'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-acs'],
      description: 'rhacs:telemetry:rox_central_secured_nodes reports RHACS secured node count.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="rhacs:telemetry:rox_central_secured_nodes"}',
    monitor_metrics: {
      '': ['rox_central_secured_nodes'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-acs'],
      description: 'rhacs:telemetry:rox_central_secured_vcpus reports RHACS secured vCPU count.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="rhacs:telemetry:rox_central_secured_vcpus"}',
    monitor_metrics: {
      '': ['rox_central_secured_vcpus'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-acs'],
      description: 'rhacs:telemetry:rox_sensor_info reports RHACS sensor information.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="rhacs:telemetry:rox_sensor_info"}',
    monitor_metrics: {
      '': ['rox_sensor_info'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-storage'],
      description: 'cluster:volume_manager_selinux_pod_context_mismatch_total reports total SELinux pod context mismatches.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:volume_manager_selinux_pod_context_mismatch_total"}',
    monitor_metrics: {
      [kubeletMonitorKey]: ['volume_manager_selinux_pod_context_mismatch_warnings_total', 'volume_manager_selinux_pod_context_mismatch_errors_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-storage'],
      description: 'cluster:volume_manager_selinux_volume_context_mismatch_warnings_total reports total SELinux volume context mismatch warnings.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:volume_manager_selinux_volume_context_mismatch_warnings_total"}',
    monitor_metrics: {
      [kubeletMonitorKey]: ['volume_manager_selinux_volume_context_mismatch_warnings_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-storage'],
      description: 'cluster:volume_manager_selinux_volume_context_mismatch_errors_total reports total SELinux volume context mismatch errors.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:volume_manager_selinux_volume_context_mismatch_errors_total"}',
    monitor_metrics: {
      [kubeletMonitorKey]: ['volume_manager_selinux_volume_context_mismatch_errors_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-storage'],
      description: 'cluster:volume_manager_selinux_volumes_admitted_total reports total SELinux volumes admitted.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:volume_manager_selinux_volumes_admitted_total"}',
    monitor_metrics: {
      [kubeletMonitorKey]: ['volume_manager_selinux_volumes_admitted_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-lightspeed'],
      description: 'ols:provider_model_configuration reports OpenShift Lightspeed provider model configuration.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="ols:provider_model_configuration"}',
    monitor_metrics: {
      '': ['ols_provider_model_configuration'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-lightspeed'],
      description: 'ols:rest_api_query_calls_total:2xx reports OpenShift Lightspeed API 2xx responses.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="ols:rest_api_query_calls_total:2xx"}',
    monitor_metrics: {
      '': ['ols_rest_api_calls_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-lightspeed'],
      description: 'ols:rest_api_query_calls_total:4xx reports OpenShift Lightspeed API 4xx responses.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="ols:rest_api_query_calls_total:4xx"}',
    monitor_metrics: {
      '': ['ols_rest_api_calls_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-lightspeed'],
      description: 'ols:rest_api_query_calls_total:5xx reports OpenShift Lightspeed API 5xx responses.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="ols:rest_api_query_calls_total:5xx"}',
    monitor_metrics: {
      '': ['ols_rest_api_calls_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-networking'],
      description: 'openshift:openshift_network_operator_ipsec_state:info reports OpenShift network operator IPsec state.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="openshift:openshift_network_operator_ipsec_state:info"}',
    monitor_metrics: {
      '': ['openshift_network_operator_ipsec_state'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-monitoring'],
      description: 'cluster:health:group_severity:count reports cluster health issues by severity.',
      label_values: {
        severity: ['critical', 'warning', 'info', 'none'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:health:group_severity:count", severity=~"critical|warning|info|none"}',
    monitor_metrics: {
      '': [],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cluster-lifecycle'],
      description: 'cluster:controlplane_topology:info reports control plane topology mode.',
      label_values: {
        mode: ['HighlyAvailable', 'HighlyAvailableArbiter', 'SingleReplica', 'DualReplica', 'External'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:controlplane_topology:info", mode=~"HighlyAvailable|HighlyAvailableArbiter|SingleReplica|DualReplica|External"}',
    monitor_metrics: {
      '': ['cluster_controlplane_topology'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-cluster-lifecycle'],
      description: 'cluster:infrastructure_topology:info reports infrastructure topology mode.',
      label_values: {
        mode: ['HighlyAvailable', 'SingleReplica'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:infrastructure_topology:info", mode=~"HighlyAvailable|SingleReplica"}',
    monitor_metrics: {
      '': ['cluster_infrastructure_topology'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/openshift-team-storage'],
      description: 'cluster:selinux_warning_controller_selinux_volume_conflict:count counts SELinux volume conflicts.',
      label_values: {},
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="cluster:selinux_warning_controller_selinux_volume_conflict:count"}',
    monitor_metrics: {
      [kubeletMonitorKey]: ['selinux_warning_controller_selinux_volume_conflict'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['@openshift/network-edge'],
      description: 'openshift:gateway_api_usage:count tracks the amount of gateway resources created in the cluster aggregated by Gateway class type.',
      label_values: {
        gateway_class_type: ['openshift', 'not-openshift'],
      },
      consumers: [],
    },
    rule: '{__name__="openshift:gateway_api_usage:count",gateway_class_type=~"openshift|not-openshift"}',
    monitor_metrics: {
      '': ['gateway_api_usage'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['https://github.com/kubev2v/forklift'],
      description: 'cluster:mtv_migrations_status_total:sum is the total number of VM migrations running on the cluster, labeled with status, provider, mode, and target.',
      label_values: {
        provider: ['ova', 'vsphere', 'openstack', 'openshift', 'ovirt', 'awsec2'],
        target: ['Local', 'Remote'],
        mode: ['Cold', 'Warm', 'RCM'],
        status: ['Succeeded', 'Failed', 'Canceled'],
      },
      consumers: [],
    },
    rule: '{__name__="cluster:mtv_migrations_status_total:sum", provider=~"ova|vsphere|openstack|openshift|ovirt|awsec2", target=~"Local|Remote", mode=~"Cold|Warm|RCM", status=~"Succeeded|Failed|Canceled"}',
    monitor_metrics: {
      '': ['mtv_migrations_status_total'],
    },
  }),
  makeEntry({
    metadata: {
      owners: ['https://github.com/integr8ly', '@boomatang'],
      description: 'rhoam_state captures the currently installed/upgrading RHOAM versions. This metric is used by cs-SRE to gain insights into RHOAM version.',
      label_values: {
        status: ['in_progress', 'complete'],
        upgrading: ['true', 'false'],
        version: ['x.y.z'],
      },
      consumers: ['@openshift/openshift-team-cluster-manager'],
    },
    rule: '{__name__="status:upgrading:version:rhoam_state:max"}',
    monitor_metrics: {
      '': ['rhoam_state'],
    },
  }),
];

{
  cmoMonitors: cmoMonitors,
  entries: entries,
}
