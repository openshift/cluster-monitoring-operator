package metrics

var (
	EtcdMinimal = []string{
		"etcd_disk_backend_commit_duration_seconds_bucket",
		"etcd_disk_wal_fsync_duration_seconds_bucket",
		"etcd_mvcc_db_total_size_in_bytes",
		"etcd_mvcc_db_total_size_in_use_in_bytes",
		"etcd_network_peer_round_trip_time_seconds_bucket",
		"etcd_network_peer_sent_failures_total",
		"etcd_server_has_leader",
		"etcd_server_is_leader",
		"etcd_server_proposals_failed_total",
		"etcd_server_quota_backend_bytes",
		"grpc_server_handled_total",
		"grpc_server_handling_seconds_bucket",
		"grpc_server_started_total",
	}

	KubeletMinimal = []string{
		// https-metrics
		"apiserver_audit_event_total",
		"kubelet_certificate_manager_client_expiration_renew_errors",
		"kubelet_containers_per_pod_count_sum",
		"kubelet_node_name",
		"kubelet_pleg_relist_duration_seconds_bucket",
		"kubelet_pod_worker_duration_seconds_bucket",
		"kubelet_server_expiration_renew_errors",
		"kubelet_volume_stats_available_bytes",
		"kubelet_volume_stats_capacity_bytes",
		"kubelet_volume_stats_inodes",
		"kubelet_volume_stats_inodes_free",
		"kubelet_volume_stats_inodes_used",
		"kubelet_volume_stats_used_bytes",
		// /metrics/cadvisor
		"container_cpu_usage_seconds_total",
		"container_fs_usage_bytes",
		"container_memory_cache",
		"container_memory_rss",
		"container_memory_swap",
		"container_memory_usage_bytes",
		"container_memory_working_set_bytes",
		"container_spec_cpu_shares",
		"machine_cpu_cores",
		"machine_memory_bytesmachine_cpu_cores",
		"machine_memory_bytes",
	}
)
