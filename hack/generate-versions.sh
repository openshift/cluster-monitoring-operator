#!/bin/bash
#
# A naive way to generate `jsonnet/versions.json` file from downstream forks
# It uses `VERSION` file located in each repository or a special function to figure out version
#
# Script is based on following ones:
# - https://github.com/prometheus-operator/kube-prometheus/blob/main/scripts/generate-versions.sh
# - https://github.com/thaum-xyz/ankhmorpork/blob/master/hack/version-update.sh
#

set -uo pipefail

TMP_BIN="$(pwd)/tmp/bin"

# Ensure that we use the binaries from the versions defined in hack/tools/go.mod.
PATH="${TMP_BIN}:${PATH}"

# Set default variable values
: "${VERSION_FILE:=jsonnet/versions.yaml}"
: "${INTERACTIVE:=true}"

version_from_remote() {
	if [ "$1" = "openshift/grafana" ]; then
		curl --retry 5 --silent --fail "https://raw.githubusercontent.com/${1}/master/package.json" | jq -r '.version'
	else
		curl --retry 5 --silent --fail "https://raw.githubusercontent.com/${1}/master/VERSION"
	fi
}

# Fallback mechanism when VERSION file is empty or not found
version_from_user() {
	ver=""
	echo >&2 -n "Cannot determine version of ${1}. Please provide version manually (without alphabetical prefixes) and press ENTER: "
	read -r ver
	echo "$ver"
}

CONTENT="$(gojsontoyaml -yamltojson <"${VERSION_FILE}")"

COMPONENTS="$(echo "$CONTENT" | jq -r '.repos | keys[]')"

for c in $COMPONENTS; do
	LOCAL=$(echo "$CONTENT" | jq -r --arg COMPONENT "$c" '.versions[$COMPONENT]')

	SLUG=$(echo "$CONTENT" | jq -r --arg COMPONENT "$c" '.repos[$COMPONENT]')
	REMOTE="$(version_from_remote "$SLUG")"
	REMOTE="${REMOTE#v}"

	if [ "$REMOTE" = "" ] && [ "$INTERACTIVE" != "true" ]; then
		REMOTE="$LOCAL"
	fi

	if [ "$REMOTE" = "" ] && [ "$INTERACTIVE" = "true" ]; then
		REMOTE="$(version_from_user "${c}")"
	fi

	if [ "$REMOTE" != "$LOCAL" ]; then
		echo >&2 "Version upgrade of ${c} from '${LOCAL}' to '${REMOTE}'"
		CONTENT=$(echo "$CONTENT" | jq --arg "COMPONENT" "${c}" --arg "VERSION" "${REMOTE}" '.versions[$COMPONENT] = $VERSION')
	fi
done

cat <<EOF >"${VERSION_FILE}"
---
# This file is meant to be managed by hack/generate-versions.sh script
# Versions provided here are mapped to 'app.kubernetes.io/version' label in all generated manifests

$(echo "$CONTENT" | gojsontoyaml)
EOF
