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
# selectors can select a single metric (e.g. '{__name__="foo"}') or all
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
    # owners: (@openshift/openshift-team-cincinnati)
    #
    # cluster_version reports what payload and version the cluster is being
    # configured to and is used to identify what versions are on a cluster that
    # is experiencing problems.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="cluster_version"}'
    #
    # owners: (@openshift/openshift-team-cincinnati)
    #
    # cluster_version_available_updates reports the channel and version server
    # the cluster is configured to use and how many updates are available. This
    # is used to ensure that updates are being properly served to clusters.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="cluster_version_available_updates"}'
    #
    # owners: (@openshift/openshift-team-cincinnati)
    #
    # cluster_version_capability reports the names of enabled and available
    # cluster capabilities.  This is used to gauge the popularity of optional
    # components and exposure to any component-specific issues.
    - '{__name__="cluster_version_capability"}'
    #
    # owners: (@openshift/openshift-team-cincinnati)
    #
    # cluster_operator_up reports the health status of the core cluster
    # operators - like up, an upgrade that fails due to a configuration value
    # on the cluster will help narrow down which component is affected.
    #
    # consumers: (@openshift/openshift-team-olm, @openshift/openshift-team-cluster-manager)
    - '{__name__="cluster_operator_up"}'
    #
    # owners: (@openshift/openshift-team-cincinnati)
    #
    # cluster_operator_conditions exposes the status conditions cluster
    # operators report for debugging. The condition and status are reported.
    #
    # consumers: (@openshift/openshift-team-olm, @openshift/openshift-team-cluster-manager)
    - '{__name__="cluster_operator_conditions"}'
    #
    # owners: (@openshift/openshift-team-cincinnati)
    #
    # cluster_version_payload captures how far through a payload the cluster
    # version operator has progressed and can be used to identify whether
    # a particular payload entry is causing failures during upgrade.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="cluster_version_payload"}'
    #
    # owners: (@openshift/openshift-team-installer, @openshift/openshift-team-cincinnati)
    #
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
    # Only alerts with valid severity label values are sent. The values are
    # defined by
    # https://github.com/openshift/enhancements/blob/master/enhancements/monitoring/alerting-consistency.md
    #
    # consumers: (@openshift/openshift-team-olm, @openshift/openshift-team-cluster-manager)
    - '{__name__="ALERTS",alertstate="firing",severity=~"critical|warning|info|none"}'
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
    # cnv_abnormal represents the reason why the operator might have an issue
    # and includes the container, and reason labels.
    - '{__name__="cnv_abnormal", reason=~"memory_working_set_delta_from_request|memory_rss_delta_from_request"}'
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
    # odf_system_raw_capacity_total_bytes gives the size of storage cluster in bytes. This is a specific OCS metric.
    - '{__name__="odf_system_raw_capacity_total_bytes"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # odf_system_raw_capacity_used_bytes is the amount of storage cluster storage used in bytes.
    - '{__name__="odf_system_raw_capacity_used_bytes"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # odf_system_health_status gives the storage cluster health status
    - '{__name__="odf_system_health_status"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # job:ceph_osd_metadata:count is the total count of osds.
    - '{__name__="job:ceph_osd_metadata:count"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # job:kube_pv:count is the total number of Persistent Volumes created by ODF present in OCP cluster.
    # This metric is deprecated in ODF 4.12, refer to job:odf_system_pvs:count instead.
    - '{__name__="job:kube_pv:count"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # job:odf_system_pvs:count is the total number of Persistent Volumes created by ODF present in OCP cluster.
    - '{__name__="job:odf_system_pvs:count"}'
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
    # This metric is deprecated in ODF 4.12, refer to odf_system_bucket_count instead.
    - '{__name__="job:noobaa_bucket_count:sum"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # job:noobaa_total_object_count:sum is the total number of noobaa objects.
    # This metric is deprecated in ODF 4.12, refer to odf_system_objects_total instead.
    - '{__name__="job:noobaa_total_object_count:sum"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # odf_system_bucket_count is the total number of buckets in ODF system
    - '{__name__="odf_system_bucket_count", system_type="OCS", system_vendor="Red Hat"}'
    #
    # owners: (@openshift/team-ocs-committers)
    #
    # odf_system_objects_total is the total number of objects in ODF system
    - '{__name__="odf_system_objects_total", system_type="OCS", system_vendor="Red Hat"}'
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
    # owners: (@openshift/hybrid-application-console-maintainers)
    # cluster:console_auth_login_requests_total:sum gives the total number of login requests initiated from the web console.
    #
    - '{__name__="cluster:console_auth_login_requests_total:sum"}'
    #
    # owners: (@openshift/hybrid-application-console-maintainers)
    # cluster:console_auth_login_successes_total:sum gives the total number of successful logins initiated from the web console.
    # Labels:
    # * `role`, one of `kubeadmin`, `cluster-admin` or `developer`. The value is based on whether or not the logged-in user can list all namespaces.
    #
    - '{__name__="cluster:console_auth_login_successes_total:sum"}'
    #
    # owners: (@openshift/hybrid-application-console-maintainers)
    # cluster:console_auth_login_failures_total:sum gives the total number of login failures initiated from the web console.
    # This might include canceled OAuth logins depending on the user OAuth provider/configuration.
    # Labels:
    # * `reason`, currently always `unknown`
    #
    - '{__name__="cluster:console_auth_login_failures_total:sum"}'
    #
    # owners: (@openshift/hybrid-application-console-maintainers)
    # cluster:console_auth_logout_requests_total:sum gives the total number of logout requests sent from the web console.
    # Labels:
    # * `reason`, currently always `unknown`
    #
    - '{__name__="cluster:console_auth_logout_requests_total:sum"}'
    #
    # owners: (@openshift/hybrid-application-console-maintainers)
    # cluster:console_usage_users:max contains the number of web console users splitten into the roles.
    # Labels:
    # * `role`: `kubeadmin`, `cluster-admin` or `developer`. The value is based on whether or not the user can list all namespaces.
    #
    - '{__name__="cluster:console_usage_users:max"}'
    #
    # owners: (@openshift/hybrid-application-console-maintainers)
    # cluster:console_plugins_info:max reports information about the web console plugins and their state.
    # Labels:
    # * `name`: `redhat`, `demo` or `other`.
    # * `state`: `enabled`, `disabled` or `notfound`
    #
    - '{__name__="cluster:console_plugins_info:max"}'
    #
    # owners: (@openshift/hybrid-application-console-maintainers)
    # cluster:console_customization_perspectives_info:max reports information about customized web console perspectives.
    # Labels:
    # * `name`, one of `admin`, `dev`, `acm` or `other`
    # * `state`, one of `enabled`, `disabled`, `only-for-cluster-admins`, `only-for-developers` or `custom-permissions`
    #
    - '{__name__="cluster:console_customization_perspectives_info:max"}'
    #
    # owners: (@openshift/networking)
    #
    # cluster:ovnkube_controller_egress_routing_via_host:max informs if the OVN-K cluster's gateway mode is
    # `routingViaOVN` (0), `routingViaHost` (1) or invalid (2).
    - '{__name__="cluster:ovnkube_controller_egress_routing_via_host:max"}'
    #
    # owners: (@openshift/networking)
    #
    # cluster:ovnkube_controller_admin_network_policies_db_objects:max informs the total number of
    # OVN database objects (table_name) owned by admin network policies in the cluster.
    # Labels:
    # * `table_name`: `ACL` or `Address_Set`.
    #
    - '{__name__="cluster:ovnkube_controller_admin_network_policies_db_objects:max",table_name=~"ACL|Address_Set"}'
    #
    # owners: (@openshift/networking)
    #
    # cluster:ovnkube_controller_baseline_admin_network_policies_db_objects:max informs the total number of
    # OVN database objects (table_name) owned by baseline admin network policies in the cluster.
    # Labels:
    # * `table_name`: `ACL` or `Address_Set`.
    #
    - '{__name__="cluster:ovnkube_controller_baseline_admin_network_policies_db_objects:max",table_name=~"ACL|Address_Set"}'
    #
    # owners: (@openshift/networking)
    #
    # cluster:ovnkube_controller_admin_network_policies_rules:max informs the total number of
    # admin network policy rules in the cluster
    # Labels:
    # * `direction`: `Ingress` or `Egress`.
    # * `action`: `Pass` or `Allow` or `Deny`.
    #
    - '{__name__="cluster:ovnkube_controller_admin_network_policies_rules:max",direction=~"Ingress|Egress",action=~"Pass|Allow|Deny"}'
    #
    # owners: (@openshift/networking)
    #
    # cluster:ovnkube_controller_baseline_admin_network_policies_rules:max informs the total number of
    # baseline admin network policy rules in the cluster
    # Labels:
    # * `direction`: `Ingress` or `Egress`.
    # * `action`: `Allow` or `Deny`.
    #
    - '{__name__="cluster:ovnkube_controller_baseline_admin_network_policies_rules:max",direction=~"Ingress|Egress",action=~"Allow|Deny"}'
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
    # owners: (@openshift/network-edge)
    #
    # cluster:ingress_controller_aws_nlb_active:sum informs how many NLBs are active in AWS.
    # Zero would indicate ELB (legacy). This metric is only emitted on AWS.
    - '{__name__="cluster:ingress_controller_aws_nlb_active:sum"}'
    #
    # owners: (@openshift/network-edge)
    #
    # cluster:route_metrics_controller_routes_per_shard:min tracks the minimum number of routes
    # admitted by any of the shards.
    - '{__name__="cluster:route_metrics_controller_routes_per_shard:min"}'
    #
    # owners: (@openshift/network-edge)
    #
    # cluster:route_metrics_controller_routes_per_shard:max tracks the maximum number of routes
    # admitted by any of the shards.
    - '{__name__="cluster:route_metrics_controller_routes_per_shard:max"}'
    #
    # owners: (@openshift/network-edge)
    #
    # cluster:route_metrics_controller_routes_per_shard:avg tracks the average value for the
    # route_metrics_controller_routes_per_shard metric.
    - '{__name__="cluster:route_metrics_controller_routes_per_shard:avg"}'
    #
    # owners: (@openshift/network-edge)
    #
    # cluster:route_metrics_controller_routes_per_shard:median tracks the median value for the
    # route_metrics_controller_routes_per_shard metric.
    - '{__name__="cluster:route_metrics_controller_routes_per_shard:median"}'
    #
    # owners: (@openshift/network-edge)
    #
    # cluster:openshift_route_info:tls_termination:sum tracks the number of routes for each tls_termination
    # value. The possible values for tls_termination are edge, passthrough and reencrypt.
    - '{__name__="cluster:openshift_route_info:tls_termination:sum"}'
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
    # owners: (@openshift/openshift-team-monitoring)
    #
    # profile:cluster_monitoring_operator_collection_profile:max contains information about the configured
    # collection profile.
    # Possible label values are:
    #   profile: full|minimal (refer: cluster-monitoring-operator/pkg/manifests#SupportedCollectionProfiles)
    - '{__name__="profile:cluster_monitoring_operator_collection_profile:max"}'
    #
    # owners: (@openshift/openshift-team-monitoring)
    #
    # vendor_model:node_accelerator_cards:sum reports the total number of accelerator cards
    # in the cluster per vendor and model.
    # Possible label values are:
    #   vendor: NVIDIA, AMD, GAUDI, INTEL, QUALCOMM
    - '{__name__="vendor_model:node_accelerator_cards:sum",vendor=~"NVIDIA|AMD|GAUDI|INTEL|QUALCOMM"}'
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
    # owners: (https://github.com/integr8ly, @boomatang)
    #
    # rhoam_state captures the currently installed/upgrading RHOAM versions.
    # Possible label values are:
    #   status= in progress|complete
    #   upgrading= true|false
    #   version= x.y.z
    # This metric is used by cs-SRE to gain insights into RHOAM version.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="status:upgrading:version:rhoam_state:max"}'
    #
    # owners: (https://github.com/integr8ly, @boomatang)
    #
    # rhoam_critical_alerts count of RHOAM specific critical alerts on a cluster
    # Possible label values are:
    #   state= pending|firing
    # This metric is used by CS-SRE to gain insights into critical alerts on RHOAM cluster.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="state:rhoam_critical_alerts:max"}'
    #
    # owners: (https://github.com/integr8ly, @boomatang)
    #
    # rhoam_warning_alerts count of RHOAM specific warning alerts on a cluster
    # Possible label values are:
    #   state= pending|firing
    # This metric is used by CS-SRE to gain insights into warning alerts on RHOAM cluster.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="state:rhoam_warning_alerts:max"}'
    #
    # rhoam_7d_slo_percentile:max Current cluster 7 day percentile
    # Possible labels: None
    # This metric is used by CS-SRE to monitor the SLO budget across the fleet.
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="rhoam_7d_slo_percentile:max"}'
    #
    # rhoam_7d_slo_remaining_error_budget:max Time in milliseconds of remaining error budget
    # Possible labels: None
    # This metric is used byt CS-SRE to monitor remaining error budget across the fleet
    #
    # consumers: (@openshift/openshift-team-cluster-manager)
    - '{__name__="rhoam_7d_slo_remaining_error_budget:max"}'
    #
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
    # owners: (https://github.com/orgs/stolostron/teams/server-foundation, @acm-server-foundation)
    #
    # acm_managed_cluster_info provides Subscription watch and other information for the managed clusters for an ACM Hub cluster.
    - '{__name__="acm_managed_cluster_info"}'
    #
    # owners: (https://github.com/orgs/stolostron/teams/server-foundation, @acm-server-foundation)
    #
    # acm_managed_cluster_worker_cores:max tracks the number of CPU cores on the worker nodes of the ACM managed clusters.
    - '{__name__="acm_managed_cluster_worker_cores:max"}'
    #
    # owners: (https://github.com/orgs/stolostron/teams/search-admin, @acm-observability-search)
    #
    # acm_console_page_count:sum counts the total number of visits for each page in ACM console.
    - '{__name__="acm_console_page_count:sum", page=~"overview-classic|overview-fleet|search|search-details|clusters|application|governance"}'
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
    # owners: (@tracing-team)
    #
    # Number of Tempo instances per backend storage type.
    - '{__name__="type:tempo_operator_tempostack_storage_backend:sum",type=~"azure|gcs|s3"}'
    #
    # owners: (@tracing-team)
    #
    # Number of Tempo instances per management state.
    - '{__name__="state:tempo_operator_tempostack_managed:sum",state=~"Managed|Unmanaged"}'
    #
    # owners: (@tracing-team)
    #
    # Number of Tempo instances per multitenancy mode.
    - '{__name__="type:tempo_operator_tempostack_multi_tenancy:sum",type=~"static|openshift|disabled"}'
    #
    # owners: (@tracing-team)
    #
    # Number of Tempo stacks with Jaeger UI enabled/disabled.
    - '{__name__="enabled:tempo_operator_tempostack_jaeger_ui:sum",enabled=~"true|false"}'
    #
    # owners: (@tracing-team)
    #
    # Number of OpenTelemetry collectors using certain receiver types.
    - '{__name__="type:opentelemetry_collector_receivers:sum",type=~"jaeger|hostmetrics|opencensus|prometheus|zipkin|kafka|filelog|journald|k8sevents|kubeletstats|k8scluster|k8sobjects|otlp"}'
    #
    # owners: (@tracing-team)
    #
    # Number of OpenTelemetry collectors used certain exporter type
    - '{__name__="type:opentelemetry_collector_exporters:sum",type=~"debug|logging|otlp|otlphttp|prometheus|lokiexporter|kafka|awscloudwatchlogs|loadbalancing"}'
    #
    # owners: (@tracing-team)
    #
    # Number of OpenTelemetry collectors used certain processor type
    - '{__name__="type:opentelemetry_collector_processors:sum",type=~"batch|memorylimiter|attributes|resource|span|k8sattributes|resourcedetection|filter|routing|cumulativetodelta|groupbyattrs"}'
    #
    # owners: (@tracing-team)
    #
    # Number of OpenTelemetry collectors used certain extension type
    - '{__name__="type:opentelemetry_collector_extensions:sum",type=~"zpages|ballast|memorylimiter|jaegerremotesampling|healthcheck|pprof|oauth2clientauth|oidcauth|bearertokenauth|filestorage"}'
    #
    # owners: (@tracing-team)
    #
    # Number of OpenTelemetry collectors used certain connector type
    - '{__name__="type:opentelemetry_collector_connectors:sum",type=~"spanmetrics|forward"}'
    #
    # owners: (@tracing-team)
    #
    # Number of OpenTelemetry collectors deployed using certain deployment type
    - '{__name__="type:opentelemetry_collector_info:sum",type=~"deployment|daemonset|sidecar|statefulset"}'
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
    # owners: (@openshift/team-build-api)
    #
    # openshift_csi_share_configmap measures amount of config maps shared by csi shared resource driver.
    - '{__name__="openshift_csi_share_configmap"}'
    #
    # owners: (@openshift/team-build-api)
    #
    # openshift_csi_share_secret measures amount of secrets shared by csi shared resource driver.
    - '{__name__="openshift_csi_share_secret"}'
    #
    # owners: (@openshift/team-build-api)
    #
    # openshift_csi_share_mount_failures_total measures amount of failed attempts to mount csi shared resources into the pods.
    - '{__name__="openshift_csi_share_mount_failures_total"}'
    #
    # owners: (@openshift/team-build-api)
    #
    # openshift_csi_share_mount_requests_total measures total amount of attempts to mount csi shared resources into the pods.
    - '{__name__="openshift_csi_share_mount_requests_total"}'
    #
    # elasticsearch operator metrics for Telemetry
    # owners: (@openshift/team-logging)
    #
    # Number of storages types used across the fleet.
    - '{__name__="eo_es_storage_info"}'
    #
    # elasticsearch operator metrics for Telemetry
    # owners: (@openshift/team-logging)
    #
    # Number of redundancy policies used across the fleet.
    - '{__name__="eo_es_redundancy_policy_info"}'
    #
    # elasticsearch operator metrics for Telemetry
    # owners: (@openshift/team-logging)
    #
    # Number of namespaces deleted per policy across the fleet.
    - '{__name__="eo_es_defined_delete_namespaces_total"}'
    #
    # elasticsearch operator metrics for Telemetry
    # owners: (@openshift/team-logging)
    #
    # Number of clusters with misconfigured memory resources across the fleet.
    - '{__name__="eo_es_misconfigured_memory_resources_info"}'
    #
    # elasticsearch operator metrics for Telemetry
    # owners: (@openshift/team-logging)
    #
    # Number of data nodes per cluster.
    - '{__name__="cluster:eo_es_data_nodes_total:max"}'
    #
    # elasticsearch operator metrics for Telemetry
    # owners: (@openshift/team-logging)
    #
    # Number of documents created per cluster.
    - '{__name__="cluster:eo_es_documents_created_total:sum"}'
    #
    # elasticsearch operator metrics for Telemetry
    # owners: (@openshift/team-logging)
    #
    # Number of documents deleted per cluster.
    - '{__name__="cluster:eo_es_documents_deleted_total:sum"}'
    #
    # elasticsearch operator metrics for Telemetry
    # owners: (@openshift/team-logging)
    #
    # Number of shards per cluster.
    - '{__name__="pod:eo_es_shards_total:max"}'
    #
    # elasticsearch operator metrics for Telemetry
    # owners: (@openshift/team-logging)
    #
    # es Management state used by the cluster.
    - '{__name__="eo_es_cluster_management_state_info"}'
    #
    # owners: (@openshift/openshift-team-image-registry)
    #
    # imageregistry:imagestreamtags_count:sum is the total number of existent image stream tags.
    - '{__name__="imageregistry:imagestreamtags_count:sum"}'
    #
    # owners: (@openshift/openshift-team-image-registry)
    #
    # imageregistry:operations_count:sum is the total number of image pushes and pulls executed in the internal registry.
    - '{__name__="imageregistry:operations_count:sum"}'
    #
    # owners: (@openshift/team-logging)
    #
    # log_logging_info gives cluster-logging-operator version, managedStatus, healthStatus specific info.
    - '{__name__="log_logging_info"}'
    #
    # owners: (@openshift/team-logging)
    #
    # log_collector_error_count_total gives cluster-logging-operator deployed collector's (e.g. default collector fluentd) total number of failures in standing it up part of logging pipeline.
    - '{__name__="log_collector_error_count_total"}'
    #
    # owners: (@openshift/team-logging)
    #
    # log_forwarder_pipeline_info gives cluster-logging-operator deployed logging pipelines info - healthStatus and pipelineInfo as no of total logging pipelines deployed.
    - '{__name__="log_forwarder_pipeline_info"}'
    #
    # owners: (@openshift/team-logging)
    #
    # log_forwarder_input_info gives cluster-logging-operator logging pipelines input types info - namely application, infra, audit type of log sources input.
    - '{__name__="log_forwarder_input_info"}'
    #
    # owners: (@openshift/team-logging)
    #
    # log_forwarder_output_info gives cluster-logging-operator logging pipelines output types info - namely to which output end point logs are being directed for further pushing them to a persistent storage.
    - '{__name__="log_forwarder_output_info"}'
    #
    # owners: (@openshift/team-logging)
    #
    # cluster:log_collected_bytes_total:sum gives total bytes collected by the collector and aggregated at each cluster level
    - '{__name__="cluster:log_collected_bytes_total:sum"}'
    #
    # owners: (@openshift/team-logging)
    #
    # cluster:log_logged_bytes_total:sum gives total bytes logged by the containers and aggregated at each cluster level
    - '{__name__="cluster:log_logged_bytes_total:sum"}'
    #
    # owners: (@openshift/team-logging)
    #
    # openshift_logging:log_forwarder_pipelines:sum number of logging pipelines in each namespace
    - '{__name__="openshift_logging:log_forwarder_pipelines:sum"}'
    #
    # owners: (@openshift/team-logging)
    #
    # openshift_logging:log_forwarders:sum number of ClusterLogForwarder instances in each namespace
    - '{__name__="openshift_logging:log_forwarders:sum"}'
    #
    # owners: (@openshift/team-logging)
    #
    # openshift_logging:log_forwarder_input_type:sum number of inputs per namespace
    - '{__name__="openshift_logging:log_forwarder_input_type:sum"}'
    #
    # owners: (@openshift/team-logging)
    #
    # openshift_logging:log_forwarder_output_type:sum number of outputs per namespace
    - '{__name__="openshift_logging:log_forwarder_output_type:sum"}'
    #
    # owners: (@openshift/team-logging)
    #
    # openshift_logging:vector_component_received_bytes_total:rate5m total number of collected log bytes per namespace
    - '{__name__="openshift_logging:vector_component_received_bytes_total:rate5m"}'
    #
    # owners: (@openshift/sandboxed-containers-operator)
    #
    # cluster:kata_monitor_running_shim_count:sum provides the number of VM
    # running with kata containers on the cluster
    - '{__name__="cluster:kata_monitor_running_shim_count:sum"}'
    #
    # owners: (@openshift/team-hypershift-maintainers)
    #
    # platform:hypershift_hostedclusters:max is the total number of clusters managed by the hypershift operator by cluster platform
    - '{__name__="platform:hypershift_hostedclusters:max"}'
    #
    # owners: (@openshift/team-hypershift-maintainers)
    #
    # platform:hypershift_nodepools:max is the total number of nodepools managed by the hypershift operator by cluster platform
    - '{__name__="platform:hypershift_nodepools:max"}'
    #
    # owners: (@openshift/team-hypershift-maintainers)
    #
    # cluster_name:hypershift_nodepools_size:sum is the total number of desired nodepool replicas managed by the hypershift operator per HostedCluster identified by `the cluster_name` and `exported_namespace` labels.
    - '{__name__="cluster_name:hypershift_nodepools_size:sum"}'
    #
    # owners: (@openshift/team-hypershift-maintainers)
    #
    # cluster_name:hypershift_nodepools_available_replicas:sum is the actual number of available nodepool replicas managed by the hypershift operator per HostedCluster identified by `the cluster_name` and `exported_namespace` labels.
    - '{__name__="cluster_name:hypershift_nodepools_available_replicas:sum"}'
    #
    # owners: (https://github.com/red-hat-storage/mcg-osd-deployer, Data Federation team)
    #
    # Number of unhealthy Object Bucket Claims in addon's namespace.
    - '{__name__="namespace:noobaa_unhealthy_bucket_claims:max"}'
    #
    # owners: (https://github.com/red-hat-storage/mcg-osd-deployer, Data Federation team)
    #
    # Number of Object Bucket Claims in addon's namespace.
    - '{__name__="namespace:noobaa_buckets_claims:max"}'
    #
    # owners: (https://github.com/red-hat-storage/mcg-osd-deployer, Data Federation team)
    #
    # Number of unhealthy namespace resources in addon's namespace.
    - '{__name__="namespace:noobaa_unhealthy_namespace_resources:max"}'
    #
    # owners: (https://github.com/red-hat-storage/mcg-osd-deployer, Data Federation team)
    #
    # Number of namespace resources in addon's namespace.
    - '{__name__="namespace:noobaa_namespace_resources:max"}'
    #
    # owners: (https://github.com/red-hat-storage/mcg-osd-deployer, Data Federation team)
    #
    # Number of unhealthy namespace buckets in addon's namespace.
    - '{__name__="namespace:noobaa_unhealthy_namespace_buckets:max"}'
    #
    # owners: (https://github.com/red-hat-storage/mcg-osd-deployer, Data Federation team)
    #
    # Number of namespace buckets in addon's namespace.
    - '{__name__="namespace:noobaa_namespace_buckets:max"}'
    #
    # owners: (https://github.com/red-hat-storage/mcg-osd-deployer, Data Federation team)
    #
    # Number of corresponding noobaa accounts in addon's namespace.
    - '{__name__="namespace:noobaa_accounts:max"}'
    #
    # owners: (https://github.com/red-hat-storage/mcg-osd-deployer, Data Federation team)
    #
    # Total usage of the noobaa system storage resources in the addon's namespace.
    - '{__name__="namespace:noobaa_usage:max"}'
    #
    # owners: (https://github.com/red-hat-storage/mcg-osd-deployer, Data Federation team)
    #
    # Status of the noobaa service in the addon's namespace.
    - '{__name__="namespace:noobaa_system_health_status:max"}'
    #
    # owners: (https://github.com/red-hat-storage/ocs-operator, OCS Operator team)
    #
    # ocs_advanced_feature_usage shows whether the cluster is using any of the advanced
    # features, like external cluster mode or KMS/PV Encryption etc
    - '{__name__="ocs_advanced_feature_usage"}'
    #
    # owners: (https://github.com/openshift/machine-config-operator/)
    #
    # os_image_url_override:sum tells whether cluster is using default OS image or has been overridden by user
    - '{__name__="os_image_url_override:sum"}'
    #
    # owners: (https://github.com/openshift/vmware-vsphere-csi-driver-operator, @openshift/storage)
    #
    # cluster:vsphere_topology_tags:max shows how many vSphere topology tag categories are configured.
    - '{__name__="cluster:vsphere_topology_tags:max"}'
    #
    # owners: (https://github.com/openshift/vmware-vsphere-csi-driver-operator, @openshift/storage)
    #
    # cluster:vsphere_infrastructure_failure_domains:max shows how many vSphere failure domains, vCenters, datacenters and datastores are configured in a cluster.
    - '{__name__="cluster:vsphere_infrastructure_failure_domains:max"}'
    #
    # owners: (@openshift/openshift-team-api, @polynomial)
    #
    # apiserver_list_watch_request_success_total:rate:sum represents the rate of change for successful LIST and WATCH requests over a 5 minute period.
    - '{__name__="apiserver_list_watch_request_success_total:rate:sum", verb=~"LIST|WATCH"}'
    #
    # owners: (https://github.com/stackrox/stackrox, @stackrox/eng)
    #
    # rhacs:telemetry:rox_central_info provides information about a Central instance of a Red Hat Advanced
    # Cluster Security installation.
    # Expected labels:
    # - build: "release" or "internal".
    # - central_id: unique ID identifying the Central instance.
    # - central_version: the product's full version.
    # - hosting: "cloud-service" or "self-managed".
    # - install_method: "operator", "manifest" or "helm".
    - '{__name__="rhacs:telemetry:rox_central_info"}'
    #
    # owners: (https://github.com/stackrox/stackrox, @stackrox/eng)
    #
    # rhacs:telemetry:rox_central_secured_clusters provides the number of clusters secured by a Central instance of a
    # Red Hat Advanced Cluster Security installation.
    # Expected labels:
    # - central_id: unique ID identifying the Central instance.
    - '{__name__="rhacs:telemetry:rox_central_secured_clusters"}'
    #
    # owners: (https://github.com/stackrox/stackrox, @stackrox/eng)
    #
    # rhacs:telemetry:rox_central_secured_nodes provides the number of nodes secured by a Central instance of a
    # Red Hat Advanced Cluster Security installation.
    # Expected labels:
    # - central_id: unique ID identifying the Central instance.
    - '{__name__="rhacs:telemetry:rox_central_secured_nodes"}'
    #
    # owners: (https://github.com/stackrox/stackrox, @stackrox/eng)
    #
    # rhacs:telemetry:rox_central_secured_vcpus provides the number of vCPUs secured by a Central instance of a
    # Red Hat Advanced Cluster Security installation.
    # Expected labels:
    # - central_id: unique ID identifying the Central instance.
    - '{__name__="rhacs:telemetry:rox_central_secured_vcpus"}'
    #
    # owners: (https://github.com/stackrox/stackrox, @stackrox/eng)
    #
    # rhacs:telemetry:rox_sensor_info provides information about a Sensor instance of a Red Hat Advanced
    # Cluster Security installation.
    # Expected labels:
    # - build: "release" or "internal".
    # - central_id: unique ID identifying the Central instance.
    # - hosting: "cloud-service" or "self-managed".
    # - install_method: "operator", "manifest" or "helm".
    # - sensor_id: unique ID identifying the Sensor instance.
    # - sensor_version: the product's full version.
    - '{__name__="rhacs:telemetry:rox_sensor_info"}'
    #
    # owners: (https://github.com/openshift/cluster-storage-operator, @openshift/storage)
    #
    # cluster:volume_manager_selinux_pod_context_mismatch_total shows how many Pods have two or more containers that have each a different SELinux context. These containers will not be able to start when SELinuxMountReadWriteOncePod feature is extended to all volumes.
    - '{__name__="cluster:volume_manager_selinux_pod_context_mismatch_total"}'
    #
    # owners: (https://github.com/openshift/cluster-storage-operator, @openshift/storage)
    #
    # cluster:volume_manager_selinux_volume_context_mismatch_warnings_total shows how many Pods would not be able to start when SELinuxMountReadWriteOncePod feature is extended to all volumes, because they use a single volume and have a different SELinux contexts each.
    - '{__name__="cluster:volume_manager_selinux_volume_context_mismatch_warnings_total"}'
    #
    # owners: (https://github.com/openshift/cluster-storage-operator, @openshift/storage)
    #
    # cluster:volume_manager_selinux_volume_context_mismatch_errors_total shows how many Pods did not start because they use a single ReadWriteOncePod volume and have a different SELinux context.
    - '{__name__="cluster:volume_manager_selinux_volume_context_mismatch_errors_total"}'
    #
    # owners: (https://github.com/openshift/cluster-storage-operator, @openshift/storage)
    #
    # cluster:volume_manager_selinux_volumes_admitted_total shows how many Pods had set SELinux context and successfuly started.
    - '{__name__="cluster:volume_manager_selinux_volumes_admitted_total"}'
    #
    # owners: (https://github.com/openshift/lightspeed-service, @openshift/team-openshift-lightspeed)
    #
    # ols:provider_model_configuration shows which providers and models are configured and enabled
    - '{__name__="ols:provider_model_configuration"}'
    #
    # owners: (https://github.com/openshift/lightspeed-service, @openshift/team-openshift-lightspeed)
    #
    # ols:rest_api_query_calls_total:2xx shows the count of successful ols query requests
    - '{__name__="ols:rest_api_query_calls_total:2xx"}'
    #
    # owners: (https://github.com/openshift/lightspeed-service, @openshift/team-openshift-lightspeed)
    #
    # ols:rest_api_query_calls_total:4xx shows the count of ols query calls that were rejected due to auth or other validity issues
    - '{__name__="ols:rest_api_query_calls_total:4xx"}'
    #
    # owners: (https://github.com/openshift/lightspeed-service, @openshift/team-openshift-lightspeed)
    #
    # ols:rest_api_query_calls_total:5xx shows the count of ols query calls that failed due to internal OLS errors (which may include errors interacting with external services such as LLM providers)
    - '{__name__="ols:rest_api_query_calls_total:5xx"}'
    #
    # owners: (https://github.com/openshift/cluster-network-operator @openshift/networking)
    #
    # openshift:openshift_network_operator_ipsec_state:info shows the cluster ipsec status (Disabled, External, Full) and whether the legacy or new API was used to set the status
    - '{__name__="openshift:openshift_network_operator_ipsec_state:info"}'
    #
    # owners: (https://github.com/openshift/cluster-health-analyzer)
    #
    # cluster:health:group_severity:count shows the total number of firing incidents by severity
    # Expected labels:
    # - severity: "critical", "warning", "info" or "none".
    - '{__name__="cluster:health:group_severity:count", severity=~"critical|warning|info|none"}'
    #
    # owners: (https://github.com/openshift/cluster-kube-apiserver-operator/)
    #
    # cluster:controlplane_topology:info shows the clusters control plane
    # topology
    - '{__name__="cluster:controlplane_topology:info", mode=~"HighlyAvailable|HighlyAvailableArbiter|SingleReplica|DualReplica|External"}'
    #
    # owners: (https://github.com/openshift/cluster-kube-apiserver-operator/)
    #
    # cluster:infrastructure_topology:info shows the clusters infrastructure
    # topology
    - '{__name__="cluster:infrastructure_topology:info", mode=~"HighlyAvailable|SingleReplica"}'
kind: ConfigMap
metadata:
  name: telemetry-config
  namespace: openshift-monitoring
  annotations:
    include.release.openshift.io/hypershift: "true"
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
```

These attributes provide a snapshot of the health, usage, and size of a cluster. From this we can determine the functionality of the framework components. This information helps Red Hat to identify correlations between issues experienced across many OpenShift 4 clusters that have similar environmental characteristics. This enables Red Hat to rapidly develop changes in OpenShift 4 to improve software resilience and customer experience.

In some situations it might be necessary to opt out of remote health reporting. For more information on this topic, please see [Opting out of remote health reporting](https://docs.openshift.com/container-platform/latest/support/remote_health_monitoring/opting-out-of-remote-health-reporting.html) in the OpenShift Container Platform 4 documentation.
