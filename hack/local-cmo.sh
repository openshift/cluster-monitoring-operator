#!/usr/bin/env bash
set -eu -o pipefail

# Global Config
declare LOGIN_AS_CMO=true
declare SHOW_USAGE=false
declare DRY_RUN=${DRY_RUN:-false}

# constants
PROJECT_ROOT="$(git rev-parse --show-toplevel)"

declare -r PROJECT_ROOT
declare -r CMO_KUBECONFIG="$PROJECT_ROOT/tmp/cmo-kubeconfig"
declare -r MON_NS='openshift-monitoring'

info() {
	echo " 🔔 $*" >&2
}

ok() {
	echo " ✅ $*" >&2
}

err() {
	echo " 🛑 $*" >&2
}

die() {
	echo -e "\n ✋ $* " >&2
	echo -e "──────────────────── ⛔️⛔️⛔️ ────────────────────────\n" >&2
	exit 1
}

run() {
	echo -e " ❯  $*\n" >&2
	$DRY_RUN && return 0

	"$@"
}

kc() {
	run kubectl -n "$MON_NS" "$@"
}

validate() {
	local ret=0

	[[ -z ${KUBECONFIG+xxx} ]] && {
		err "KUBECONFIG is not defined"
		ret=1
	}

	gojsontoyaml --help 2>/dev/null || {
		err "gojsontoyaml not found. See: https://github.com/brancz/gojsontoyaml#install"
		ret=1
	}

	jq --version >/dev/null || {
		err "jq not found. See: https://stedolan.github.io/jq/download/"
		ret=1
	}

	ok "validations passed"

	return $ret
}

disable_managed_cmo() {
	# NOTE: we can't kubectl patch the spec.overrides since 'overrides'
	# does not define the patch strategy.
	# See: https://kubernetes.io/docs/tasks/manage-kubernetes-objects/update-api-object-kubectl-patch/#notes-on-the-strategic-merge-patch
	#
	# So, as a workaround, we get the entire contents of the `spec.overrides` and
	# use jq to merge the override that puts "cluster-monitoring-operator" in
	# unmanaged state.

	local merge
	merge=$(
		cat <<-__EOF
			    {
			      "spec": {
			        "overrides": [
			          [ .spec | .? | .overrides[] | .? | select(.name != "cluster-monitoring-operator")] +
			          [{
			            "group": "apps",
			            "kind": "Deployment",
			            "name": "cluster-monitoring-operator",
			            "namespace": "$MON_NS",
			            "unmanaged": true
			          }]
			        ] | flatten
			      }
			    }
		__EOF
	)

	local overrides
	overrides=$(kubectl get clusterversion version -o json | jq "$merge" | gojsontoyaml)
	run kubectl patch clusterversion/version --type=merge -p="$overrides"

	info "Disabling incluster operator "
	kc scale --replicas=0 deployment/cluster-monitoring-operator
}

images_from_deployment() {
	kubectl -n "$MON_NS" get deployment cluster-monitoring-operator -o json |
		jq -r '.spec.template.spec.containers[] | select(.name=="cluster-monitoring-operator") | .args[] | select(.|test("\\-images.*"))'
}

#create as new kubeconfig for cmo service-account
create_cmo_kubeconfig() {
	local cmo_kubeconfig="$1"
	shift

	local cmo_token="$PROJECT_ROOT/tmp/cmo-token"
	local api_server
	api_server=$(oc whoami --show-server)

	# NOTE: do not generate KUBECONFIG if the its already usable
	if [[ -f "$cmo_kubeconfig" ]]; then
		run oc --kubeconfig="$cmo_kubeconfig" get prometheus -n "$MON_NS" && return 0
	fi

	info "Generating a new token for CMO at - $cmo_token"
	run oc create -n "$MON_NS" token cluster-monitoring-operator >"$cmo_token"
	echo -n >"$cmo_kubeconfig"

	info "Creating a new KUBECONFIG file for CMO at - $cmo_kubeconfig"
	run oc --kubeconfig="$cmo_kubeconfig" login --token="$(cat "$cmo_token")" "$api_server"
	run oc --kubeconfig="$cmo_kubeconfig" whoami
	run oc --kubeconfig="$cmo_kubeconfig" project openshift-monitoring
	run oc --kubeconfig="$cmo_kubeconfig" get prometheus -n "$MON_NS"
}

parse_args() {
	### while there are args parse them
	while [[ -n "${1+xxx}" ]]; do
		case $1 in
		-h | --help)
			SHOW_USAGE=true
			break
			;; # exit the loop
		--dry-run)
			DRY_RUN=true
			shift
			;;
		-x | --no-cmo-login)
			LOGIN_AS_CMO=false
			shift
			;;
		*) return 1 ;; # show usage on everything else
		esac
	done
	return 0
}

print_usage() {
	local scr
	scr="$(basename "$0")"

	read -r -d '' help <<-EOF_HELP || true
		$scr performs the following actions:
		  1. Patches CVO to configure the cluster-monitoring-operator (CMO) in unmanaged mode.
		  2. Scales down the in-cluster CMO to 0.
		  3. Creates a new kubeconfig files for CMO service-account.
		  4. Changes the currently logged-in user to the CMO service account.
		  5. Executes the CMO locally (using go run)

		Usage: $scr [options]

		Options:
		  * -h | --help:         Display this help message.
		  * -x | --no-cmo-login: Run the operator as the currently logged-in user. (default: false)
		  *      --dry-run:      Do not execute and command, only print them

	EOF_HELP

	echo -e "$help"
	return 0

}

main() {
	parse_args "$@" || {
		print_usage
		die "parsing arguments failed; see usage and options above"
	}

	$SHOW_USAGE && {
		print_usage
		exit 0
	}

	# go to project root so that all paths are relative to it
	cd "$PROJECT_ROOT"
	run mkdir -p "$PROJECT_ROOT/tmp"

	validate || exit 1
	disable_managed_cmo

	local operator_config=manifests/0000_50_cluster-monitoring-operator_04-config.yaml
	local telemetry_conf=/tmp/telemetry-config.yaml

	gojsontoyaml -yamltojson <$operator_config |
		jq -r '.data["metrics.yaml"]' >$telemetry_conf

	# NOTE: can't use readarray as it is missing in OSX
	local -a images
	while read -r img; do images+=("$img"); done < <(images_from_deployment)

	local kubeconfig="$KUBECONFIG"
	$LOGIN_AS_CMO && {
		create_cmo_kubeconfig "$CMO_KUBECONFIG"
		kubeconfig="$CMO_KUBECONFIG"
	}

	info "Running operator as $(oc --kubeconfig="$kubeconfig" whoami)"

	run go run ./cmd/operator/... "${images[@]}" \
		-assets assets/ \
		-telemetry-config $telemetry_conf \
		-kubeconfig="$kubeconfig" \
		-namespace=openshift-monitoring \
		-configmap=cluster-monitoring-config \
		-logtostderr=true -v=4 2>&1 | tee tmp/operator.log
}

main "$@"
