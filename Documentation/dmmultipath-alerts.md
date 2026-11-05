# DM-multipath alerts

CMO includes DM-multipath device health alerts in `node-exporter-rules` in
`openshift-monitoring`. Platform Prometheus evaluates the node-exporter metrics.
The alerts cover all reported DM-multipath devices, including devices used by
non-VM workloads. Both the full and minimal collection profiles retain the
metrics required by these alerts.

The rules are adapted from the [DM-multipath alerts in openshift-monitoring-addson](https://github.com/raffaelespazzoli/openshift-monitoring-addson/blob/ac4eedcf0454121af010d8954cf85bd8a975c929/storage/alerts.yaml).
They preserve its names, thresholds, and durations:

- `MultipathPathDegraded`: warning after any failed paths persist for 5 minutes.
- `MultipathPathCritical`: critical after at least half the paths have failed
  for 2 minutes, with at least one failed path. This includes total path loss.
- `MultipathDeviceSuspended`: critical after the device is suspended for 1 minute.

The warning and critical path alerts can fire together. A path is counted as
active when its device state is SCSI `running` or NVMe `live`. These metrics
report underlying device state, not multipathd path-checker or ALUA state.
The critical threshold also applies to devices with only one path.

## Prerequisites and compatibility

The platform node-exporter must expose `node_dmmultipath_device_paths_failed`,
`node_dmmultipath_device_paths`, and `node_dmmultipath_device_active`.
Check for these metrics in **Observe → Metrics** before relying on the alerts.

The collector is enabled by default and its configuration key is
`nodeExporter.collectors.dmMultipath`. The node-exporter collector itself is
called `dmmultipath`. Availability depends on the installed OpenShift release;
consult that release's monitoring documentation before changing configuration.
These rules do not change collector configuration.

On older releases without these metrics, when the collector is disabled, or
when no multipath devices exist, the alerts produce no series and do not fire.
Metric absence does not establish that storage is healthy.

## MultipathPathDegraded and MultipathPathCritical

Use the alert's `instance`, `device`, and `sysfs_name` labels to identify the
node and device. Inspect `multipath -ll` and the underlying paths on that node.
Check physical connectivity, HBA and switch ports, zoning, iSCSI sessions where
applicable, and array controller health. Compare the failed and total path
metrics for the same instance and device to determine the remaining redundancy.

Restore failed paths with the storage administrator. If all paths are lost,
check affected workloads for blocked I/O. Verify that path counts recover and
the alerts resolve. Do not remove a mapped device while workloads are using it.

## MultipathDeviceSuspended

Inspect `dmsetup info` and `dmsetup status` for the named device on the affected
node. Determine whether a storage operation intentionally suspended it and
check the underlying path and storage health. Coordinate with the component
or administrator managing the device before resuming it. Once the underlying
issue is resolved, restore the device and verify that I/O resumes and
`node_dmmultipath_device_active` returns to `1`.
