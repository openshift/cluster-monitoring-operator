#!/bin/sh
if [ "$IS_CONTAINER" != "" ]; then
  yamllint "${@}"
else
  docker run --rm \
    --env IS_CONTAINER=TRUE \
    --volume "${PWD}:/workdir:z" \
    --entrypoint sh \
    quay.io/coreos/yamllint \
    ./hack/yamllint.sh "${@}"
fi;
