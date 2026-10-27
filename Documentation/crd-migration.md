# ConfigMap to CRD Migration

## Overview

The Cluster Monitoring Operator is migrating platform monitoring configuration from ConfigMaps
to a strongly-typed Custom Resource Definition (CRD). The new `ClusterMonitoring` CRD
(`config.openshift.io/v1alpha1`) provides benefits over ConfigMaps including:

- Typed API with CEL validation at admission time
- Discoverability through standard Kubernetes tooling (`kubectl explain`)
- Status subresource for reporting reconciliation state
- Schema versioning and conversion webhooks

This migration is gated behind the `ClusterMonitoringConfig` feature gate and is currently
available only in **TechPreview** and **DevPreview** clusters.

## Feature Gate

The `ClusterMonitoringConfig` feature gate controls whether the operator watches and merges
configuration from the `ClusterMonitoring` CR. When the gate is disabled (default in GA clusters),
the operator ignores the CR entirely and uses only ConfigMaps.

The gate is defined in `openshift/api` and enabled in TechPreview/DevPreview feature sets:

```go
FeatureGateClusterMonitoringConfig = newFeatureGate("ClusterMonitoringConfig").
    reportProblemsToJiraComponent("Monitoring").
    enable(inTechPreviewNoUpgrade(), inDevPreviewNoUpgrade()).
    mustRegister()
```

## Architecture

### Configuration Sources

| Source | Scope | Status |
|--------|-------|--------|
| `cluster-monitoring-config` ConfigMap (openshift-monitoring) | Platform monitoring | GA |
| `user-workload-monitoring-config` ConfigMap (openshift-user-workload-monitoring) | User workload monitoring | GA |
| `ClusterMonitoring` CR named `cluster` (config.openshift.io/v1alpha1) | Platform monitoring | TechPreview |

### Configuration Loading Pipeline

```text
 ┌──────────────────────────────┐   ┌──────────────────────────────┐
 │  cluster-monitoring-config   │   │   ClusterMonitoring CR       │
 │  ConfigMap                   │   │   (if feature gate enabled)  │
 └──────────────┬───────────────┘   └──────────────┬───────────────┘
                │                                  │
                ▼                                  │
 NewConfigFromConfigMapAndClusterMonitoringResource()
                │                                  │
                ▼                                  │
        Unmarshal ConfigMap YAML                   │
        into ClusterMonitoringConfiguration        │
                │                                  │
                ▼                                  ▼
        mergeClusterMonitoringCRD() ◄──────────────┘
        (Phase 1: ConfigMap wins per component)
                │
                ▼
        applyDefaults()
                │
                ▼
        validate()
                │
                ▼
        Config struct drives reconciliation
```

Entry points in `pkg/manifests/config.go`:
- `NewConfigFromConfigMapAndClusterMonitoringResource()`
- `NewConfigFromStringAndClusterMonitoringResource()`

The operator (`pkg/operator/operator.go`) watches the `ClusterMonitoring` CR via an informer
only when the `ClusterMonitoringConfig` feature gate is enabled, and fetches the singleton
CR named `cluster` via `GetClusterMonitoring(ctx, "cluster")`.

## Phase 1 Merge Semantics (Pre-GA)

Phase 1 uses a **ConfigMap-primary** approach:

- For each top-level component (e.g., `prometheusK8s`, `alertmanagerMain`, `metricsServer`),
  if the ConfigMap sets that component (even to `{}`), the entire CRD section for that component
  is ignored.
- CRD values are only applied when the ConfigMap does **not** configure that component
  (the internal pointer is `nil` after unmarshaling the ConfigMap).
- The merge runs **before** `applyDefaults()`, so nil-checks reflect user intent from the
  ConfigMap, not post-default state.

This means users can adopt the CRD incrementally, component by component, while keeping
existing ConfigMap-based configuration for components they have not yet migrated.

### Implementation

The merge logic lives in:
- `pkg/manifests/config_merge.go` — main merge function and per-component merges
- `pkg/manifests/config_merge_prometheus.go` — Prometheus-specific merge
- `pkg/manifests/config_merge_test.go` — unit tests for Phase 1 precedence

## Phase 2 (Future / GA)

Phase 2 will invert the precedence: the CRD becomes the primary configuration source and
the ConfigMap is deprecated. Details are not yet finalized.

## Field Mapping

### Components with CRD merge implemented

| CRD field (`ClusterMonitoringSpec`) | ConfigMap field (`ClusterMonitoringConfiguration`) | Notes |
|-------------------------------------|---------------------------------------------------|-------|
| `userDefined.mode` | `enableUserWorkload` | `Isolated` maps to `true` |
| `prometheusConfig` | `prometheusK8s` | Full config including remote write, retention, collection profile |
| `alertmanagerConfig` | `alertmanagerMain` | Includes deployment mode and custom config |
| `metricsServerConfig` | `metricsServer` | Scheduling, resources, audit, verbosity |
| `prometheusOperatorConfig` | `prometheusOperator` | Scheduling, resources, log level |
| `prometheusOperatorAdmissionWebhookConfig` | `prometheusOperatorAdmissionWebhook` | Resources, topology constraints |
| `monitoringPluginConfig` | `monitoringPlugin` | Scheduling, resources |
| `telemeterClientConfig` | `telemeterClient` | Scheduling and resources only |
| `thanosQuerierConfig` | `thanosQuerier` | Scheduling and resources only |
| `openShiftStateMetricsConfig` | `openshiftStateMetrics` | Scheduling, resources |
| `kubeStateMetricsConfig` | `kubeStateMetrics` | Scheduling, resources, additional resource labels |
| `nodeExporterConfig` | `nodeExporter` | Resources, max procs, collectors (policy-based) |

### ConfigMap-only fields (no CRD equivalent)

| ConfigMap field | Reason |
|-----------------|--------|
| `http` (HTTPConfig) | Not yet added to CRD |
| `k8sPrometheusAdapter` | Deprecated, will be removed |
| `userWorkload.rulesWithoutLabelEnforcementAllowed` | Not yet added to CRD |
| `telemeterClient.enabled`, `clusterID`, `token`, `telemeterServerURL` | Operational/secret fields not suitable for CRD |
| Entire `UserWorkloadConfiguration` | No CRD equivalent; remains ConfigMap-only |

### CRD fields not yet mapped to internal config

| CRD field | Internal equivalent | Status |
|-----------|-------------------|--------|
| `alertmanagerConfig.customConfig.userAlertmanagerConfigSelection` | `enableUserAlertmanagerConfig` | Not yet mapped |
| `thanosQuerierConfig.requestLogging` | `enableRequestLogging` | Not yet mapped |
| `thanosQuerierConfig.logLevel` | `logLevel` | Not yet mapped |

## CRD API Reference

The `ClusterMonitoring` CRD types are defined in the openshift/api repository:

- **Types**: [config/v1alpha1/types_cluster_monitoring.go](https://github.com/openshift/api/blob/master/config/v1alpha1/types_cluster_monitoring.go)
- **API approval**: [openshift/api PR #1929](https://github.com/openshift/api/pull/1929)

The CRD is deployed by the `config-operator` (not CMO). CMO has read-only RBAC for `clustermonitorings`.

## Key Files

| File | Purpose |
|------|---------|
| `vendor/github.com/openshift/api/config/v1alpha1/types_cluster_monitoring.go` | CRD type definitions |
| `pkg/manifests/types.go` | ConfigMap configuration schema |
| `pkg/manifests/config.go` | Config loading and merge entry points |
| `pkg/manifests/config_merge.go` | CRD-to-ConfigMap merge logic |
| `pkg/manifests/config_merge_prometheus.go` | Prometheus-specific CRD merge |
| `pkg/manifests/config_merge_test.go` | Phase 1 precedence unit tests |
| `pkg/operator/operator.go` | Operator watch and config aggregation |
| `pkg/client/client.go` | ClusterMonitoring client helpers |
| `test/e2e/cluster_monitoring_test.go` | E2E tests for CRD configuration |
