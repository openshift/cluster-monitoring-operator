# AI Agent Guidance for Cluster Monitoring Operator

This file provides guidance to AI agents when working with code in this repository.

This is the Cluster Monitoring Operator (CMO) - the operator that manages the Prometheus-based monitoring stack in
OpenShift. CMO is deployed by the Cluster Version Operator (CVO).

## Architecture Overview

### Jsonnet Manifest Generation

CMO generates Kubernetes manifests using Jsonnet (`jsonnet/`):

- Source: `jsonnet/components/*.libsonnet` and vendored upstream jsonnet
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
[cluster-bot](https://github.com/openshift/ci-chat-bot) via Slack (Red Hat internal). In Slack, message `@cluster-bot`
with `launch 4.17` (or desired version) to get a temporary cluster with credentials.

```bash
export KUBECONFIG=/path/to/kubeconfig      # Requires OpenShift cluster
make run-local                             # Build and run locally as CMO service account
make run-local SWITCH_TO_CMO=false         # Run as current user (e.g., kube:admin)
```

### Jsonnet Workflow

```bash
# Modify jsonnet source files in jsonnet/
make generate          # Regenerate manifests, docs, and metadata
make docs              # Regenerate documentation only (api.md, resources.md)
make check-assets      # Verify assets are up to date
```

**Rapid iteration**: For quick testing, you can modify YAML files in `assets/` directly, run the operator with
`hack/local-cmo.sh` (no rebuild needed), then port changes back to jsonnet. See `Documentation/development.md` for
detailed workflow.

**Two-release annotation/label removal**: To remove a label/annotation from a resource managed by `CreateOrUpdateXXX`
functions:

1. First release: Add suffix `"-"` to the annotation/label (CMO deletes it via library-go)
2. Second release: Remove from jsonnet source

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
Run `make tests-ext-update` after modifying Ginkgo tests to update metadata.

### Verification

```bash
make verify            # Run all checks
make format            # Format code (go fmt, jsonnet fmt, shellcheck)
make golangci-lint     # Lint Go code
make check-rules       # Validate Prometheus rules with promtool
```

## OpenShift Conventions

### Pull Requests

- **Title format**: `OCPBUGS-12345: descriptive title` (bugs) or `MON-1234: descriptive title` (features)
  - Example: `MON-4435: Add RBAC permission for endpointslice resource in UWM prometheus-operator`
  - Example: `OCPBUGS-61088: create networkpolicy settings for in-cluster monitoring`
- **Commit format**: `<subsystem>: <what changed>`
  - Example: `jsonnet: update prometheus version`
  - Example: `e2e: add e2e test to verify endpointslice discovery in uwm`
- All PRs require JIRA ticket reference

### Jira Integration

- **Automatic linking**: PRs are automatically linked to JIRA when the key is in the PR title
- **Lifecycle automation**: [jira-lifecycle-plugin](https://github.com/openshift-eng/jira-lifecycle-plugin) updates
  JIRA status based on PR events
- **Jira commands** (comment on PR):
  - `/jira refresh` - Manually sync PR with JIRA issue
  - `/jira cc @username` - CC someone on the JIRA issue
  - `/jira backport <branch>` - Create backport PR to target branch (e.g., `/jira backport release-4.17`)
  - `/jira assign <user>` - Assign the JIRA issue to specified user
  - `/jira unassign` - Remove current assignee from JIRA issue
  - `/jira comment <comment>` - Add comment to the JIRA issue
  - `/jira close` - Close the JIRA issue
  - `/jira reopen` - Reopen the JIRA issue
- **Creating tickets**: Use OCPBUGS project for bugs, MON project for features
- **Required fields**: Component (Monitoring), Target Version, Priority
- **Status workflow**: To Do → In Progress → Code Review → Done

### Prow CI

- **Triggering tests**: Tests run automatically on PR creation/update
- **Useful commands** (comment on PR):
  - `/retest` - Retry all failed tests
  - `/test <job-name>` - Run specific job (e.g., `/test e2e-aws`)
  - `/test-with <job-name>` - Run specific job with additional tests
  - `/retitle <new-title>` - Change PR title
  - `/assign @username` - Assign reviewer
  - `/cc @username` - Request review without assignment
  - `/hold` - Prevent auto-merge, `/hold cancel` to remove
  - `/lgtm` - Approve PR (maintainers only)
  - `/approve` - Approve for merge (maintainers only)
  - `/cherry-pick <branch>` - Cherry-pick to another branch after merge
- **Important jobs**:
  - `ci/prow/images` - Builds container images
  - `ci/prow/e2e-*` - E2E test variants
  - `ci/prow/verify` - Runs `make verify`
  - `ci/prow/unit` - Unit tests
- **Viewing results**: Click "Details" next to job to see Prow logs
- **Common failures**:
  - `ci/prow/images` fails if `make verify` would fail (run locally first)
  - E2E timeouts may be transient (retry with `/retest`)
- **More commands**: See [prow.ci.openshift.org/command-help](https://prow.ci.openshift.org/command-help)

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
4. **Wrong cluster type**: Tests require OpenShift, not vanilla Kubernetes
5. **Stale local CMO**: Make sure you have the right permissions when running locally for development or the operator
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
