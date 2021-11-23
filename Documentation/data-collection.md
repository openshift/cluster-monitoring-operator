# OpenShift 4 Data Collection

Red Hat values our customers' experience and privacy. It is important to us that our customers understand exactly what we are sending back to Red Hat Engineering and why. We want to be able to make changes to our designs and coding practices rapidly, based on our customers' environments. The faster the feedback loop the better.

OpenShift 4 clusters send anonymized telemetry back to Red Hat about the following attributes. The telemetry is gathered by referencing your cluster ID and pull secret:

[embedmd]:# (../manifests/0000_50_cluster-monitoring-operator_04-config.yaml)
```yaml
# This configmap is used by the cluster monitoring operator to configure the
# telemeter client which is in charge of reading the metrics from the
# in-cluster Prometheus instances and forwarding them to the Telemetry service.
#
# The only supported key in metrics.yaml is "matches" which is a list of label
# selectors that define which metrics are going to be forwarded. Label
# selectors can select an single metric (e.g. '{__name__="foo"}') or all
# metric names matching a regexp (e.g. '{__name__=~"foo:.+"}').
#
# Every entry should be commented with the owners (GitHub handles preferred)
# and a short description of the metric(s). It is also possible to mention the
# consumers (again handles preferred) so that any change to the metric can be
# communicated to the right audience.
apiVersion: v1
data:
  metrics.yaml: |-
    matches:
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # cluster:usage recording rules summarize important usage information
    # about the cluster that points to specific features or component usage
    # that may help identify problems or specific workloads. For example,
    # cluster:usage:openshift:build:rate24h would show the number of builds
    # executed within a 24h period so as to determine whether the current
    # cluster is using builds and may be susceptible to eviction due to high
    # disk usage from build temporary directories.
    # All metrics under this prefix must have low (1-5) cardinality and must
    # be well-scoped and follow proper naming and scoping conventions.
    - '{__name__=~"cluster:usage:.*"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # count:up0 contains the count of cluster monitoring sources being marked as down.
    # This information is relevant to the health of the registered
    # cluster monitoring sources on a cluster. This metric allows telemetry
    # to identify when an update causes a service to begin to crash-loop or
    # flake.
    - '{__name__="count:up0"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # count:up1 contains the count of cluster monitoring sources being marked as up.
    # This information is relevant to the health of the registered
    # cluster monitoring sources on a cluster. This metric allows telemetry
    # to identify when an update causes a service to begin to crash-loop or
    # flake.
    - '{__name__="count:up1"}'
    #
    # owners: (@openshift/openshift-team-installer)
    #
    # cluster_version reports what payload and version the cluster is being
    # configured to and is used to identify what versions are on a cluster that
    # is experiencing problems.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="cluster_version"}'
    #
    # owners: (@openshift/openshift-team-installer)
    #
    # cluster_version_available_updates reports the channel and version server
    # the cluster is configured to use and how many updates are available. This
    # is used to ensure that updates are being properly served to clusters.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="cluster_version_available_updates"}'
    #
    # owners: (@openshift/openshift-team-installer)
    #
    # cluster_operator_up reports the health status of the core cluster
    # operators - like up, an upgrade that fails due to a configuration value
    # on the cluster will help narrow down which component is affected.
    #
    # consumers: (@openshift/openshift-team-olm, @openshift/openshift-team-cluster-manager)
    - '{__name__="cluster_operator_up"}'
    #
    # owners: (@openshift/openshift-team-installer)
    #
    # cluster_operator_conditions exposes the status conditions cluster
    # operators report for debugging. The condition and status are reported.
    #
    # consumers: (@openshift/openshift-team-olm, @openshift/openshift-team-cluster-manager)
    - '{__name__="cluster_operator_conditions"}'
    #
    # owners: (@openshift/openshift-team-installer)
    #
    # cluster_version_payload captures how far through a payload the cluster
    # version operator has progressed and can be used to identify whether
    # a particular payload entry is causing failures during upgrade.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="cluster_version_payload"}'
    #
    # owners: (@openshift/openshift-team-installer)
    #
    # owners: (@openshift/openshift-team-olm)
    # cluster_installer reports what installed the cluster, along with its
    # version number and invoker.
    #
    # consumers: (@openshift/openshift-team-olm)
    - '{__name__="cluster_installer"}'
    #
    # owners: (@openshift/openshift-team-master, @smarterclayton)
    #
    # cluster_infrastructure_provider reports the configured cloud provider if
    # any, along with the infrastructure region when running in the public
    # cloud.
    #
    # consumers: (@openshift/openshift-team-olm, @openshift/openshift-team-cluster-manager)
    - '{__name__="cluster_infrastructure_provider"}'
    #
    # owners: (@openshift/openshift-team-master, @smarterclayton)
    #
    # cluster_feature_set reports the configured cluster feature set and
    # whether the feature set is considered supported or unsupported.
    - '{__name__="cluster_feature_set"}'
    #
    # owners: (@openshift/openshift-team-etcd, @smarterclayton)
    #
    # instance:etcd_object_counts:sum identifies two key metrics:
    # - the rough size of the data stored in etcd and
    # - the consistency between the etcd instances.
    #
    # consumers: (@openshift/openshift-team-olm)
    - '{__name__="instance:etcd_object_counts:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # alerts are the key summarization of the system state. They are reported
    # via telemetry to assess their value in detecting upgrade failure causes
    # and also to prevent the need to gather large sets of metrics that are
    # already summarized on the cluster.  Reporting alerts also creates an
    # incentive to improve per cluster alerting for the purposes of preventing
    # upgrades from failing for end users.
    #
    # consumers: (@openshift/openshift-team-olm, @openshift/openshift-team-cluster-manager)
    - '{__name__="ALERTS",alertstate="firing"}'
    #
    # owners: (@openshift/ops)
    #
    # code:apiserver_request_total:rate:sum identifies average of occurences
    # of each http status code over 10 minutes
    # The metric will be used for SLA analysis reports.
    #
    # consumers: (@openshift/openshift-team-olm)
    - '{__name__="code:apiserver_request_total:rate:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # cluster:capacity_cpu_cores:sum is the total number of CPU cores in the
    # cluster labeled by node role and type.
    #
    # consumers: (@openshift/openshift-team-olm, @openshift/openshift-team-cluster-manager)
    - '{__name__="cluster:capacity_cpu_cores:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # cluster:capacity_memory_bytes:sum is the total bytes of memory in the
    # cluster labeled by node role and type.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="cluster:capacity_memory_bytes:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # cluster:cpu_usage_cores:sum is the current amount of CPU used by
    # the whole cluster.
    #
    # consumers: (@openshift/openshift-team-olm, @openshift/openshift-team-cluster-manager)
    - '{__name__="cluster:cpu_usage_cores:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # cluster:memory_usage_bytes:sum is the current amount of memory in use
    # across the whole cluster.
    #
    # consumers: (@openshift/openshift-team-olm, @openshift/openshift-team-cluster-manager)
    - '{__name__="cluster:memory_usage_bytes:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # openshift:cpu_usage_cores:sum is the current amount of CPU used by
    # OpenShift components, including the control plane and host services
    # (including the kernel).
    #
    # consumers: (@openshift/openshift-team-olm)
    - '{__name__="openshift:cpu_usage_cores:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # openshift:memory_usage_bytes:sum is the current amount of memory used by
    # OpenShift components, including the control plane and host services
    # (including the kernel).
    - '{__name__="openshift:memory_usage_bytes:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # workload:cpu_usage_cores:sum is the current amount of CPU used by cluster
    # workloads, excluding infrastructure.
    #
    # consumers: (@openshift/openshift-team-olm)
    - '{__name__="workload:cpu_usage_cores:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # workload:memory_usage_bytes:sum is the current amount of memory used by
    # cluster workloads, excluding infrastructure.
    #
    # consumers: (@openshift/openshift-team-olm)
    - '{__name__="workload:memory_usage_bytes:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # cluster:virt_platform_nodes:sum is the number of nodes reporting
    # a particular virt_platform type (nodes may report multiple types).
    # This metric helps identify issues specific to a virtualization
    # type or bare metal.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="cluster:virt_platform_nodes:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # cluster:node_instance_type_count:sum is the number of nodes of each
    # instance type and role.
    #
    # consumers: (@openshift/openshift-team-olm, @openshift/openshift-team-cluster-manager)
    - '{__name__="cluster:node_instance_type_count:sum"}'
    #
    # owners: (https://github.com/kubevirt)
    #
    # cnv:vmi_status_running:count is the total number of VM instances running in the cluster.
    - '{__name__="cnv:vmi_status_running:count"}'
    #
    # owners: (https://github.com/kubevirt)
    #
    # cluster:vmi_request_cpu_cores:sum is the total number of CPU cores requested by pods of VMIs.
    - '{__name__="cluster:vmi_request_cpu_cores:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # node_role_os_version_machine:cpu_capacity_cores:sum is the total number
    # of CPU cores in the cluster labeled by master and/or infra node role, os,
    # architecture, and hyperthreading state.
    #
    # consumers: (@openshift/openshift-team-olm, @openshift/openshift-team-cluster-manager)
    - '{__name__="node_role_os_version_machine:cpu_capacity_cores:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring, @smarterclayton)
    #
    # node_role_os_version_machine:cpu_capacity_sockets:sum is the total number
    # of CPU sockets in the cluster labeled by master and/or infra node role,
    # os, architecture, and hyperthreading state.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="node_role_os_version_machine:cpu_capacity_sockets:sum"}'
    #
    # owners: (@openshift/openshift-team-olm)
    #
    # subscription_sync_total is the number of times an OLM operator
    # Subscription has been synced, labelled by name and installed csv
    - '{__name__="subscription_sync_total"}'
    #
    # owners: (@openshift/openshift-team-olm)
    #
    # olm_resolution_duration_seconds is the duration of a dependency resolution attempt.
    - '{__name__="olm_resolution_duration_seconds"}'
    #
    # owners: (@openshift/openshift-team-olm)
    #
    # csv_succeeded is unique to the namespace, name, version, and phase
    # labels.  The metrics is always present and can be equal to 0 or 1, where
    # 0 represents that the csv is not in the succeeded state while 1
    # represents that the csv is in the succeeded state.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="csv_succeeded"}'
    #
    # owners: (@openshift/openshift-team-olm)
    #
    # csv_abnormal represents the reason why a csv is not in the succeeded
    # state and includes the namespace, name, version, phase, reason labels.
    # When a csv is updated, the previous time series associated with the csv
    # will be deleted.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="csv_abnormal"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # cluster:kube_persistentvolumeclaim_resource_requests_storage_bytes:provisioner:sum
    # gives the total amount of storage requested by PVCs from a particular
    # storage provisioner in bytes. This is a generic storage metric.
    - '{__name__="cluster:kube_persistentvolumeclaim_resource_requests_storage_bytes:provisioner:sum"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # cluster:kubelet_volume_stats_used_bytes:provisioner:sum will gives
    # the total amount of storage used by PVCs from a particular storage provisioner in bytes.
    - '{__name__="cluster:kubelet_volume_stats_used_bytes:provisioner:sum"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # ceph_cluster_total_bytes gives the size of ceph cluster in bytes. This is a specific OCS metric.
    - '{__name__="ceph_cluster_total_bytes"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # ceph_cluster_total_used_raw_bytes is the amount of ceph cluster storage used in bytes.
    - '{__name__="ceph_cluster_total_used_raw_bytes"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # ceph_health_status gives the ceph cluster health status
    - '{__name__="ceph_health_status"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # job:ceph_osd_metadata:count is the total count of osds.
    - '{__name__="job:ceph_osd_metadata:count"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # job:kube_pv:count is the total number of Persistent Volumes present in OCP cluster.
    - '{__name__="job:kube_pv:count"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # job:ceph_pools_iops:total is the total iops (reads+writes) value for all the pools in ceph cluster
    - '{__name__="job:ceph_pools_iops:total"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # job:ceph_pools_iops:total is the total iops (reads+writes) value in bytes for all the pools in ceph cluster
    - '{__name__="job:ceph_pools_iops_bytes:total"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # job:ceph_versions_running:count is the total count of ceph cluster versions running.
    - '{__name__="job:ceph_versions_running:count"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # job:noobaa_total_unhealthy_buckets:sum is the total number of unhealthy noobaa buckets
    - '{__name__="job:noobaa_total_unhealthy_buckets:sum"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # job:noobaa_bucket_count:sum is the total number of noobaa buckets.
    - '{__name__="job:noobaa_bucket_count:sum"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # job:noobaa_total_object_count:sum is the total number of noobaa objects.
    - '{__name__="job:noobaa_total_object_count:sum"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # noobaa_accounts_num gives the count of noobaa's accounts.
    - '{__name__="noobaa_accounts_num"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # noobaa_total_usage gives the total usage of noobaa's storage in bytes.
    - '{__name__="noobaa_total_usage"}'
    #
    # owners: (@openshift/origin-web-console-committers)
    # console_url is the url of the console running on the cluster.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="console_url"}'
    #
    # owners: (@openshift/networking)
    #
    # cluster:network_attachment_definition_instances:max" gives max no of instance
    # in the cluster that are annotated with k8s.v1.cni.cncf.io/networks, labelled by networks.
    - '{__name__="cluster:network_attachment_definition_instances:max"}'
    #
    # owners: (@openshift/networking)
    #
    # cluster:network_attachment_definition_enabled_instance_up  informs (1 or 0) if the cluster has
    # at least max of one instance with  k8s.v1.cni.cncf.io/networks annotation, labelled by networks (any or sriov).
    - '{__name__="cluster:network_attachment_definition_enabled_instance_up:max"}'
    #
    # owners: (https://github.com/openshift/insights-operator/blob/master/OWNERS)
    #
    # insightsclient_request_send tracks the number of metrics sends.
    - '{__name__="insightsclient_request_send_total"}'
    #
    # owners: (@openshift/openshift-team-app-migration)
    #
    # cam_app_workload_migrations tracks number of app workload migrations
    # by current state. Tracked migration states are idle, running, completed, and failed.
    - '{__name__="cam_app_workload_migrations"}'
    #
    # owners: (@openshift/openshift-team-master)
    #
    # cluster:apiserver_current_inflight_requests:sum:max_over_time:2m gives maximum number of requests in flight
    # over a 2-minute window. This metric is a constant 4 time series that monitors concurrency of kube-apiserver and
    # openshift-apiserver with request type which can be either 'mutating' or 'readonly'.
    # We want to have an idea of how loaded our api server(s) are globally.
    - '{__name__="cluster:apiserver_current_inflight_requests:sum:max_over_time:2m"}'
    #
    # owners: (@openshift/openshift-team-monitoring)
    #
    # cluster:alertmanager_integrations:max tracks the total number of active alertmanager integrations sent via telemetry from each cluster.
    - '{__name__="cluster:alertmanager_integrations:max"}'
    #
    # owners: (@openshift/openshift-team-monitoring)
    #
    # cluster:telemetry_selected_series:count tracks the total number of series
    # sent via telemetry from each cluster.
    - '{__name__="cluster:telemetry_selected_series:count"}'
    #
    # owners: (@openshift/openshift-team-monitoring)
    #
    # openshift:prometheus_tsdb_head_series:sum tracks the total number of active series
    - '{__name__="openshift:prometheus_tsdb_head_series:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring)
    #
    # openshift:prometheus_tsdb_head_samples_appended_total:sum tracks the rate of samples ingested
    # by prometheusi.
    - '{__name__="openshift:prometheus_tsdb_head_samples_appended_total:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring)
    #
    # monitoring:container_memory_working_set_bytes:sum tracks the memory usage of the monitoring
    # stack.
    - '{__name__="monitoring:container_memory_working_set_bytes:sum"}'
    #
    # owners: (@openshift/openshift-team-monitoring)
    #
    # namespace_job:scrape_series_added:topk3_sum1h tracks the top 3 namespace/job groups which created series churns in the last hour.
    - '{__name__="namespace_job:scrape_series_added:topk3_sum1h"}'
    #
    # owners: (@openshift/openshift-team-monitoring)
    #
    # namespace_job:scrape_samples_post_metric_relabeling:topk3 tracks the top 3 prometheus targets which produced more samples.
    - '{__name__="namespace_job:scrape_samples_post_metric_relabeling:topk3"}'
    #
    # owners: (@openshift/openshift-team-monitoring)
    #
    # monitoring:haproxy_server_http_responses_total:sum tracks the number of times users access
    # monitoring routes.
    - '{__name__="monitoring:haproxy_server_http_responses_total:sum"}'
    #
    # owners: (https://github.com/integr8ly, @david-martin)
    #
    # rhmi_status reports the status of an RHMI installation.
    # Possible values are bootstrap|cloud-resources|monitoring|authentication|products|solution-explorer|deletion|complete.
    # This metric is used by OCM to detect when an RHMI installation is complete & ready to use i.e. rhmi_status{stage='complete'}
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="rhmi_status"}'
    #
    # owners: (openshift/openshift-team-master, @openshift/openshift-group-b)
    #
    # cluster_legacy_scheduler_policy reports whether the scheduler operator is
    # configured with a custom Policy file. This value is a boolean 0|1
    - '{__name__="cluster_legacy_scheduler_policy"}'
    #
    # owners: (openshift/openshift-team-master, @openshift/openshift-group-b)
    #
    # cluster_master_schedulable reports whether mastersSchedulable=true in
    # the scheduler operator. This value is a boolean 0|1
    - '{__name__="cluster_master_schedulable"}'
    #
    # owners: (https://github.com/redhat-developer/codeready-workspaces, @ibuziuk)
    #
    # The number of workspaces with a given status STARTING|STOPPED|RUNNING|STOPPING. Type 'gauge'.
    - '{__name__="che_workspace_status"}'
    #
    # owners: (https://github.com/redhat-developer/codeready-workspaces, @ibuziuk)
    #
    # The number of started workspaces. Type 'counter'.
    - '{__name__="che_workspace_started_total"}'
    #
    # owners: (https://github.com/redhat-developer/codeready-workspaces, @ibuziuk)
    #
    # The number of failed workspaces.
    # Can be used with the 'while' label e.g. {while="STARTING"}, {while="RUNNING"}, {while="STOPPING"}.Type 'counter'.
    - '{__name__="che_workspace_failure_total"}'
    #
    # owners: (https://github.com/redhat-developer/codeready-workspaces, @ibuziuk)
    #
    # The time in seconds required for the startup of all the workspaces.
    - '{__name__="che_workspace_start_time_seconds_sum"}'
    #
    # owners: (https://github.com/redhat-developer/codeready-workspaces, @ibuziuk)
    #
    # The overall number of attempts for starting all the workspaces.
    - '{__name__="che_workspace_start_time_seconds_count"}'
    #
    # owners: (@openshift/openshift-team-hive)
    #
    # Track current mode the cloud-credentials-operator is functioning under.
    - '{__name__="cco_credentials_mode"}'
    #
    # owners: (@openshift/storage)
    #
    # Persistent Volume usage metrics: this is the number of volumes per plugin
    # and per volume type (filesystem/block)
    - '{__name__="cluster:kube_persistentvolume_plugin_type_counts:sum"}'
    #
    # owners: (https://github.com/open-cluster-management, @open-cluster-management/squad-kui-admins)
    #
    # visual_web_terminal_sessions_total is the count of Visual Web Terminal sessions created
    # on the hub cluster.
    - '{__name__="visual_web_terminal_sessions_total"}'
    #
    # owners: (https://github.com/open-cluster-management, @open-cluster-management/cluster-lifecycle-admin)
    #
    # acm_managed_cluster_info provides Subscription watch and other information for the managed clusters for an ACM Hub cluster.
    - '{__name__="acm_managed_cluster_info"}'
    #
    # owners: (@openshift/storage)
    #
    # VMWare vCenter info: version of the vCenter where cluster runs
    - '{__name__="cluster:vsphere_vcenter_info:sum"}'
    #
    # owners: (@openshift/storage)
    #
    # The list of ESXi host versions used as host for OCP nodes.
    - '{__name__="cluster:vsphere_esxi_version_total:sum"}'
    #
    # owners: (@openshift/storage)
    #
    # The list of virtual machine HW versions used for OCP nodes.
    - '{__name__="cluster:vsphere_node_hw_version_total:sum"}'
    #
    # owners: (@openshift/team-build-api)
    #
    # openshift:build_by_strategy:sum measures total number of builds on a cluster, aggregated by build strategy.
    - '{__name__="openshift:build_by_strategy:sum"}'
    #
    # owners: (https://github.com/red-hat-data-services/odh-deployer, Open Data Hub team)
    #
    # This is (at a basic level) the availability of the RHODS system.
    - '{__name__="rhods_aggregate_availability"}'
    #
    # owners: (https://github.com/red-hat-data-services/odh-deployer, Open Data Hub team)
    #
    # The total number of users of RHODS using each component.
    - '{__name__="rhods_total_users"}'
    #
    # owners: (@openshift/team-etcd)
    #
    # 99th percentile of etcd WAL fsync duration.
    - '{__name__="instance:etcd_disk_wal_fsync_duration_seconds:histogram_quantile",quantile="0.99"}'
    #
    # owners: (@openshift/team-etcd)
    #
    # Sum by instance of total db size. Used for understanding and improving defrag controller.
    - '{__name__="instance:etcd_mvcc_db_total_size_in_bytes:sum"}'
    #
    # owners: (@openshift/team-etcd)
    #
    # 99th percentile of peer to peer latency.
    - '{__name__="instance:etcd_network_peer_round_trip_time_seconds:histogram_quantile",quantile="0.99"}'
    #
    # owners: (@openshift/team-etcd)
    #
    # Sum by instance of total db size in use.
    - '{__name__="instance:etcd_mvcc_db_total_size_in_use_in_bytes:sum"}'
    #
    # owners: (@openshift/team-etcd)
    #
    # 99th percentile of the backend commit duration.
    - '{__name__="instance:etcd_disk_backend_commit_duration_seconds:histogram_quantile",quantile="0.99"}'
    #
    # owners: (@tracing-team)
    #
    # Number of jaeger instances using certain storage type.
    - '{__name__="jaeger_operator_instances_storage_types"}'
    #
    # owners: (@tracing-team)
    #
    # Number of jaeger instances with certain strategy .
    - '{__name__="jaeger_operator_instances_strategies"}'
    #
    # owners: (@tracing-team)
    #
    # Number of jaeger instances used certain agent strategy
    - '{__name__="jaeger_operator_instances_agent_strategies"}'
    #
    # owners: (https://github.com/redhat-developer/application-services-metering-operator)
    #
    # The current amount of CPU used by Application Services products, aggregated by product name.
    - '{__name__="appsvcs:cores_by_product:sum"}'
    #
    # owners: (https://github.com/openshift/cluster-node-tuning-operator)
    #
    # Number of nodes using a custom TuneD profile not shipped by the Node Tuning Operator.
    - '{__name__="nto_custom_profiles:count"}'
kind: ConfigMap
metadata:
  name: telemetry-config
  namespace: openshift-monitoring
  annotations:
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
```

These attributes provide a snapshot of the health, usage, and size of a cluster. From this we can determine the functionality of the framework components. This information helps Red Hat to identify correlations between issues experienced across many OpenShift 4 clusters that have similar environmental characteristics. This enables Red Hat to rapidly develop changes in OpenShift 4 to improve software resilience and customer experience.

In some situations it might be necessary to opt out of remote health reporting. For more information on this topic, please see [Opting out of remote health reporting](https://docs.openshift.com/container-platform/4.5/support/remote_health_monitoring/opting-out-of-remote-health-reporting.html) in the OpenShift Container Platform 4 documentation.
