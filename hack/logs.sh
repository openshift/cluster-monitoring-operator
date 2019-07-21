#!/bin/bash

kubectl -n openshift-monitoring logs -f "$(kubectl -n openshift-monitoring get pods -lapp=cluster-monitoring-operator -ojson | jq -r ".items[0].metadata.name")"
