package main

// openshift/api changed where generated CRD manifests are tracked. This import
// is now required to get the CRD manifests vendored
import _ "github.com/openshift/api/monitoring/v1/zz_generated.crd-manifests"
