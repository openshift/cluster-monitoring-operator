#!/bin/bash

set -e

[ -z "$JSONNETFMT_BIN" ] && JSONNETFMT_BIN="$(which jsonnetfmt)" && export JSONNETFMT_BIN

find jsonnet/ -name 'vendor' -prune -o -name '*.libsonnet' -print0 -o -name '*.jsonnet' -print0  | xargs -0 -n 1 -- "$JSONNETFMT_BIN" -i
