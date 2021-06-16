#!/bin/bash

set -euo pipefail

TMP_BIN="$(pwd)/tmp/bin"

# Ensure that we use the binaries from the versions defined in hack/tools/go.mod.
PATH="${TMP_BIN}:${PATH}"

install() {
	version="stable" # or "v0.7.2", or "latest"
	platform=""
	if [[ "$OSTYPE" == "linux-gnu"* ]]; then
		platform="linux"
	elif [[ "$OSTYPE" == "darwin"* ]]; then
		platform="darwin"
	fi

	mkdir -p "${TMP_BIN}"
	cd "${TMP_BIN}" || exit 1

	wget -qO- "https://github.com/koalaman/shellcheck/releases/download/${version?}/shellcheck-${version?}.${platform}.x86_64.tar.xz" | tar -xJv
	cp "shellcheck-${version}/shellcheck" "${TMP_BIN}/shellcheck"
	chmod +x "${TMP_BIN}/shellcheck"
}

# Install shellcheck if it is not available
if ! command -v shellcheck 2>/dev/null; then
	install
fi

TOP_DIR="${1:-.}"
find "${TOP_DIR}" -path "${TOP_DIR}/vendor" -prune -o -path "${TOP_DIR}/jsonnet/vendor" -prune -o -type f -name '*.sh' -exec shellcheck --format=gcc {} \+
