# AI Agent Guidance for Cluster Monitoring Operator

This is the Cluster Monitoring Operator (CMO) - the operator that manages the Prometheus-based monitoring stack in
OpenShift. CMO is deployed by the Cluster Version Operator (CVO).

## Architecture

### Jsonnet Manifest Generation

Kubernetes resources managed by CMO are generated using [Jsonnet](https://jsonnet.org/) code.

- Sources
  - `jsonnet/main.jsonnet` is the top-level entrypoint putting together all the resources managed by the Cluster Monitoring Operator.
  - Each `jsonnet/components/<component>.libsonnet` file defines the Kubernetes resources for the corresponding component.
  - `jsonnet/jsonnetfile.json` defines the jsonnet dependencies. Dependency management is documented in `Documentation/development.md`.
- Outputs
  - All files located in the `assets/` directory.
  - Files located in the `manifests/` directory which contain "DO NOT EDIT".
- The operator reads the YAML manifests from `assets/` at runtime via `pkg/manifests/`

**Critical**: Changes must be made to the jsonnet source files, then regenerated with `make jsonnet-fmt generate`.
Direct edits to `assets/*/*.yaml` will be overwritten. **DO NOT** edit them directly.

### Configuration API

Two ConfigMaps control the configuration of the monitoring components:

- `cluster-monitoring-config` (openshift-monitoring) - Platform monitoring
- `user-workload-monitoring-config` (openshift-user-workload-monitoring) - User workload monitoring

The ConfigMaps are merged into the Config struct in `pkg/manifests/config.go`. All struct fields and CEL
validations and thus possible configuration values are defined in `pkg/manifests/types.go`.

### Reconciliation Task Ordering

The operator's `sync()` in `pkg/operator/operator.go` runs reconciliation tasks in three ordered groups:

1. **PrometheusOperator + MetricsScrapingClientCA** -- must run first because PO manages CRDs that all other components depend on
2. **All other components** (Prometheus, Alertmanager, node-exporter, UWM, etc.) -- run in parallel
3. **ConfigurationSharing + DefaultDenyNetworkPolicy** -- must run last because they depend on resources created by group 2

This ordering is intentional but the reasoning is not captured in code comments. Adding or reordering tasks
requires understanding these dependencies.

### Feature Gates

CMO uses OpenShift FeatureGates to control feature availability. Features go through TechPreview (gated) before
becoming GA (gate removed, enabled by default). See the
[feature-sets enhancement](https://github.com/openshift/enhancements/blob/master/enhancements/installer/feature-sets.md)
for details.

## Development

E2E tests and `make run-local` require an OpenShift cluster and `KUBECONFIG` to be set.
Use `SWITCH_TO_CMO=false` with `make run-local` to run as the current user instead of the CMO service account.

**openshift-tests-extension**: CMO integrates with the OpenShift conformance test framework via `tests-ext` binary.
Run `make tests-ext-update` after modifying Ginkgo tests to update metadata.

## OpenShift Conventions

Follow [openshift/enhancements CONVENTIONS.md](https://github.com/openshift/enhancements/blob/master/CONVENTIONS.md).

### Pull Requests & JIRA

- **Title format**: `OCPBUGS-12345: descriptive title` (bugs) or `MON-1234: descriptive title` (features)
- **Commit format**: `<subsystem>: <what changed>` (e.g., `jsonnet: update prometheus version`)
- **OCPBUGS vs MON**: OCPBUGS issues are moved through JIRA states automatically by
  [jira-lifecycle-plugin](https://github.com/openshift-eng/jira-lifecycle-plugin). MON issues are **not** bot-managed
  and must be transitioned manually.
- See the [team workflow doc](https://docs.google.com/document/d/1q5dotlhNpODhfrn0Lo3M-0hgTk2oF9wbxVhNuLYs5zE/edit?tab=t.0)
  for the full JIRA workflow.

### CI Job Results

Prow job results are stored under `artifacts/` in the job result page. Key locations:

- `build-log.txt` - Main build/test output
- `artifacts/e2e-test/` - E2E test logs and must-gather data
- `artifacts/junit*.xml` - Structured test results
- If `ci/prow/images` fails, `make verify` likely fails locally too

## Common Pitfalls

1. **Forgetting `make generate`**: Modifying jsonnet without regenerating assets causes CI failures
2. **Missing KUBECONFIG**: E2E tests fail silently if KUBECONFIG isn't set, even if `~/.kube/config` exists
3. **Asset sync issues**: Run `make clean` before `make generate` if vendored jsonnet behaves unexpectedly
4. **Stale local CMO**: Make sure you have the right permissions when running locally or the operator
   may get stuck in the reconcile loop without permissions to list or modify resources.
5. **Multi-module repo**: There are three Go modules with separate `go.mod` and `vendor/` directories:
   `./`, `test/monitoring/`, and `hack/tools/`. Dependency changes (bumps, CVE fixes) must be applied
   to all affected modules -- don't forget `go mod tidy && go mod vendor` in each.

## References

- `Documentation/development.md` - Detailed development workflows
- [Monitoring enhancements](https://github.com/openshift/enhancements/tree/master/enhancements/monitoring) -
  Design documents for monitoring features
- [OpenShift Monitoring Docs](https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/monitoring/) -
  User-facing documentation
