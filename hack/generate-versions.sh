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

MAIN_BRANCH="master"

# Set default variable values
: "${VERSION_FILE:=jsonnet/versions.yaml}"
# PULL_BASE_REF will also be set by CI
: "${PULL_BASE_REF:=master}"

if [ "$PULL_BASE_REF" != "$MAIN_BRANCH" ]; then
	echo >&2 "Components versions are only updated on '${MAIN_BRANCH}' branch for now. Nothing to do against '${PULL_BASE_REF}'."
	exit 0
fi

version_from_remote() {
	curl --retry 5 --silent --fail "https://raw.githubusercontent.com/${1}/${MAIN_BRANCH}/VERSION"
}

CONTENT="$(gojsontoyaml -yamltojson <"${VERSION_FILE}")"

COMPONENTS="$(echo "$CONTENT" | jq -r '.repos | keys[]')"

for c in $COMPONENTS; do
	LOCAL=$(echo "$CONTENT" | jq -r --arg COMPONENT "$c" '.versions[$COMPONENT]')

	SLUG=$(echo "$CONTENT" | jq -r --arg COMPONENT "$c" '.repos[$COMPONENT]')
	REMOTE="$(version_from_remote "$SLUG")"
	REMOTE="${REMOTE#v}"

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
