#!/bin/bash

kubectl port-forward -n openshift-monitoring "$(kubectl get pods -n openshift-monitoring -lapp=prometheus -ojsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')" 9090
