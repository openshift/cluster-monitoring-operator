#!/usr/bin/env bash
set -eu -o pipefail

cmo_login='true'

# Script will:
# 1. Patch CVO to exclude CMO from being managed
# 2. Scale in-cluster CMO to 0
# 3. Try to run CMO locally (CMO needs to be built before starting)


echo "script starting"

while test $# -gt 0; do
  case "$1" in
    -h|--help)
      echo "local_cmo [options]"
      echo " "
      echo "options:"
      echo "-h, --help                show brief help"
      echo "-n, --no-cmo-login        run script as kube:admin"
      exit 0
      ;;
    -n|--no-cmo-login)
      cmo_login='false'
      shift
      ;;
    *)
      break
      ;;
  esac
done

validate() {
  local ret=0

  [[ -z ${KUBECONFIG+xxx}  ]] && {
    echo "ERROR: KUBECONFIG is not defined"
    ret=1
  }

  [[ -x operator ]] || {
    echo "ERROR: Failed to find 'operator' binary."
    echo "       Did you run 'make run-local' or 'make build' ?"
    ret=1
  }

  gojsontoyaml  --help 2>/dev/null || {
    echo "ERROR: gojsontoyaml not found. See: https://github.com/brancz/gojsontoyaml#install"
    ret=1
  }

  jq --version >/dev/null || {
    echo "ERROR: jq not found. See: https://stedolan.github.io/jq/download/"
    ret=1
  }

  return $ret
}

kc() {
  kubectl -n openshift-monitoring "$@"
}

disable_managed_cmo(){
  # NOTE: we can't kubectl patch the spec.overrides since 'overrides'
  # does not define the patch strategy.
  # See: https://kubernetes.io/docs/tasks/manage-kubernetes-objects/update-api-object-kubectl-patch/#notes-on-the-strategic-merge-patch
  #
  # So, as a workaround, we get the entire contents of the `spec.overrides` and
  # use jq to merge the override that puts "cluster-monitoring-operator" in
  # unmanaged state.

  local merge
  merge=$(cat <<-__EOF
    {
      "spec": {
        "overrides": [
          [ .spec | .? | .overrides[] | .? | select(.name != "cluster-monitoring-operator")] +
          [{
            "group": "apps",
            "kind": "Deployment",
            "name": "cluster-monitoring-operator",
            "namespace": "openshift-monitoring",
            "unmanaged": true
          }]
        ] | flatten
      }
    }
__EOF
  )

  local overrides
  overrides=$(kubectl get clusterversion version -o json | jq "$merge" | gojsontoyaml)
  kubectl patch clusterversion/version --type=merge  -p="$overrides"

  echo "Disabling incluster operator "
  kc scale --replicas=0 deployment/cluster-monitoring-operator
}

images_from_deployment() {
  kc get deployment cluster-monitoring-operator -o json | jq -r '.spec.template.spec.containers[] | select(.name=="cluster-monitoring-operator") | .args[] | select(.|test("\\-images.*"))'
}

#log as cmo sa in order to be the correct user
login_as_cmo() {
	local cmo_sa="system:serviceaccount:openshift-monitoring:cluster-monitoring-operator"
  local tmp_dir="tmp/cmo_token"
	local token="$tmp_dir/cmo-token"

	# use while to break out
	while [[ -f "$token" ]]; do
		oc login -u "$cmo_sa" || {
			rm -f "$token"
			break
		}
		oc get prometheus -n openshift-monitoring && return 0
	done

	echo "create a new cmo token -> $token"
	mkdir -p "$tmp_dir"
	oc create -n openshift-monitoring token cluster-monitoring-operator >"$token"
  oc login --token="$(cat "$token")"
	oc project openshift-monitoring
	oc whoami
}

run() {
  echo "Running: $*"
  "$@"
}

main(){
  # go to project root
  cd "$(git rev-parse --show-cdup)"

  validate || exit 1
  oc login -u system:admin
  disable_managed_cmo

  local operator_config=manifests/0000_50_cluster-monitoring-operator_04-config.yaml
  local telemetry_conf=/tmp/telemetry-config.yaml

  gojsontoyaml -yamltojson  < $operator_config |
      jq -r '.data["metrics.yaml"]' > $telemetry_conf

  # NOTE: can't use readarray as it is missing in OSX
  local -a images
  while read -r img; do images+=( "$img" ); done < <(images_from_deployment)

  if [ $cmo_login == 'true' ]; then
    echo "loggin as cmo sa"
    echo "run: oc login -u system:admin when finished in order to continue as admin"
    login_as_cmo
  fi

  run ./operator "${images[@]}" \
    -assets assets/ \
    -telemetry-config $telemetry_conf \
    -kubeconfig "${KUBECONFIG}" \
    -namespace=openshift-monitoring \
    -configmap=cluster-monitoring-config \
    -logtostderr=true -v=4 2>&1 | tee operator.log
}

main "$@"
