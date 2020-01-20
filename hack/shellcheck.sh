#!/bin/sh

set -eux

if [ "${IS_CONTAINER:-}" != "" ]; then
  TOP_DIR="${1:-.}"
  find "${TOP_DIR}" \
    -path "${TOP_DIR}/vendor" -prune \
    -o -path "${TOP_DIR}/jsonnet/vendor" -prune \
    -o -type f -name '*.sh' -exec shellcheck --format=gcc {} \+
else
  docker run --rm \
    --env IS_CONTAINER=TRUE \
    --volume "${PWD}:/workdir:ro,z" \
    --entrypoint sh \
    --workdir /workdir \
    koalaman/shellcheck-alpine:stable \
    /workdir/hack/shellcheck.sh "${@}"
fi;
