# AI Agent Guidance for Cluster Monitoring Operator

This file provides guidance to AI agents when working with code in this repository.

This is the Cluster Monitoring Operator (CMO) - the operator that manages the Prometheus-based monitoring stack in
OpenShift. CMO is deployed by the Cluster Version Operator (CVO).

## Architecture Overview

### Jsonnet Manifest Generation

CMO generates Kubernetes manifests using Jsonnet (`jsonnet/`):

- Source: `jsonnet/` and vendored upstream jsonnet
- Output: `assets/` directory with generated YAML manifests
- The operator reads manifests from `assets/` at runtime via `pkg/manifests/`

**Critical**: When modifying manifests, changes must be made in jsonnet source files, then regenerated with
`make generate`. Direct edits to `assets/*.yaml` will be overwritten. **DO NOT** edit them directly.

### Configuration API

Two ConfigMaps control monitoring behavior:

- `cluster-monitoring-config` (openshift-monitoring) - Platform monitoring
- `user-workload-monitoring-config` (openshift-user-workload-monitoring) - User workload monitoring

Types defined in `pkg/manifests/types.go` with validation rules.

- **DO NOT** invent new config keys

## Development Commands

### Local Development

**Prerequisites**: You need access to an OpenShift cluster. You can provision one using
[cluster-bot](https://github.com/openshift/ci-chat-bot) via Slack (Red Hat internal). Message `@cluster-bot`
with `launch 4.17` (or desired version) or `launch <org>/<repo>#<PR>` to test from a PR.

```bash
export KUBECONFIG=/path/to/kubeconfig      # Requires OpenShift cluster
make run-local                             # Build and run locally as CMO service account
make run-local SWITCH_TO_CMO=false         # Run as current user (e.g., kube:admin)
```

### Jsonnet Workflow

```bash
# Modify jsonnet source files in jsonnet/
make generate          # Regenerate manifests, docs, and metadata
```

### Testing

```bash
make test              # All tests (requires OpenShift cluster with KUBECONFIG)
make test-unit         # Unit tests only
make test-e2e          # E2E tests (requires OpenShift cluster)
make test-ginkgo       # Ginkgo tests (ported from openshift-tests-private)

# Specific tests
go test -v ./pkg/... -run TestName                                            # Specific unit test
go test -v -timeout=120m -run TestName ./test/e2e/ --kubeconfig $KUBECONFIG   # Specific e2e test
```

**openshift-tests-extension**: CMO integrates with the OpenShift conformance test framework via `tests-ext` binary.
Run `make tests-ext-update` after modifying Ginkgo tests to update metadata. Prow runs these tests via CI jobs.

### Verification

```bash
make verify            # Run all checks
make format            # Format code (go fmt, jsonnet fmt, shellcheck)
make golangci-lint     # Lint Go code
make check-rules       # Validate Prometheus rules with promtool
```

## OpenShift Conventions

### Pull Requests & JIRA

- **Title format**: `OCPBUGS-12345: descriptive title` (bugs) or `MON-1234: descriptive title` (features)
- **Commit format**: `<subsystem>: <what changed>` (e.g., `jsonnet: update prometheus version`)
- **Automatic linking**: PRs are automatically linked to JIRA when the key is in the PR title
- **Lifecycle automation**: [jira-lifecycle-plugin](https://github.com/openshift-eng/jira-lifecycle-plugin) manages
  JIRA status and provides commands (see plugin docs for available `/jira` commands)

### Prow CI

- Tests run automatically on PR creation/update
- Use `/retest` to retry failed tests, `/test <job-name>` to run specific jobs
- See [prow.ci.openshift.org/command-help](https://prow.ci.openshift.org/command-help) for all commands
- **Analyzing failures**:
  - Click "Details" next to a failed job to view Prow logs
  - For e2e failures, check the `artifacts/` directory in job results for detailed logs
  - Common transient failures: e2e timeouts (retry with `/retest`)
  - If `ci/prow/images` fails, `make verify` likely fails locally

### Feature Development

- **FeatureGate integration**: CMO integrates with OpenShift FeatureGates for controlling feature availability
  - Example: `MetricsCollectionProfiles` feature gate controls collection profile functionality
  - Check in `pkg/operator/operator.go`: `featureGates.Enabled(features.FeatureGateMetricsCollectionProfiles)`
  - Pass to config: `CollectionProfilesFeatureGateEnabled` flag in `pkg/manifests/config.go`
- **TechPreview → GA lifecycle**:
  - TechPreview: Feature gated, requires explicit enablement
  - GA: Feature gate removed, enabled by default
- **Adding new features**:
  1. Add FeatureGate check in `pkg/operator/operator.go`
  2. Pass enabled state through config
  3. Conditionally create resources based on gate state (e.g., `serviceMonitors()` helper)
  4. Update `pkg/manifests/types.go` if new config fields needed

## Updating Jsonnet Dependencies

Example: Updating kube-prometheus bundle:

```bash
cd jsonnet

# Edit jsonnetfile.json, update version for desired component
jb update

# Stage only the version/sum changes for target bundle in jsonnetfile.lock.json
git add -p jsonnetfile.lock.json

# Revert unwanted changes
git restore jsonnetfile.json jsonnetfile.lock.json

# Reinstall with updated lockfile
rm -rf vendor && jb install

cd ..
make generate
```

See `Documentation/development.md` for detailed workflow.

## Common Pitfalls

1. **Forgetting `make generate`**: Modifying jsonnet without regenerating assets causes CI failures
2. **Missing KUBECONFIG**: E2E tests fail silently if KUBECONFIG isn't set, even if `~/.kube/config` exists
3. **Asset sync issues**: Run `make clean` before `make generate` if vendored jsonnet behaves unexpectedly
4. **Stale local CMO**: Make sure you have the right permissions when running locally for development or the operator
   may get stuck within the reconcile loop as it won't have permissions to list or modify resources.

## Documentation

- `CONTRIBUTING.md` - Contribution guidelines and workflow details
- `Documentation/development.md` - Detailed development workflows
- [OpenShift Monitoring Docs](https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/monitoring/)
  \- User-facing monitoring documentation

## Important Files

- `Makefile` - All build and test targets
- `VERSION` - Operator version string
- `manifests/` - Deployment manifests
- `OWNERS` and `OWNERS_ALIASES` - Code ownership definitions, admins.
