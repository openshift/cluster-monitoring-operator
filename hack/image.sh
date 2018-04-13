#!/bin/bash

kubectl -n openshift-monitoring get pods -lapp=cluster-monitoring-operator -ojson | jq ".items[0].spec.containers[0].image"

