// Derived from code originally published in
//
//	https://github.com/openshift/openshift-tests-private
//
// at commit a6a189840b006da18c8203950983c0cee5ea7354.
package util

import (
	"context"
	"fmt"
	"os"

	g "github.com/onsi/ginkgo/v2"
	configv1 "github.com/openshift/api/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

// SkipOnOpenShiftNess skips the test if the cluster type doesn't match the expected type.
func SkipOnOpenShiftNess(expectOpenShift bool) {
	switch IsKubernetesClusterFlag {
	case "yes":
		if expectOpenShift {
			g.Skip("Expecting OpenShift but the active cluster is not, skipping the test")
		}
	// Treat both "no" and "unknown" as OpenShift
	default:
		if !expectOpenShift {
			g.Skip("Expecting non-OpenShift but the active cluster is OpenShift, skipping the test")
		}
	}
}

// IsExternalOIDCCluster checks if the cluster is using external OIDC.
func IsExternalOIDCCluster(oc *CLI) (bool, error) {
	switch IsExternalOIDCClusterFlag {
	case "yes":
		e2e.Logf("it is external oidc cluster")
		return true, nil
	case "no":
		e2e.Logf("it is not external oidc cluster")
		return false, nil
	default:
		e2e.Logf("do not know if it is external oidc cluster or not, and try to check it again")
		authType, stdErr, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("authentication/cluster", "-o=jsonpath={.spec.type}").Outputs()
		if err != nil {
			return false, fmt.Errorf("error checking if the cluster is using external OIDC: %v", stdErr)
		}
		e2e.Logf("Found authentication type used: %v", authType)
		return authType == string(configv1.AuthenticationTypeOIDC), nil
	}
}

// IsKeycloakExtOIDCCluster assumes the cluster uses external oidc auth but checks if the oidc issuer is Keycloak.
func IsKeycloakExtOIDCCluster() bool {
	if os.Getenv("KEYCLOAK_ISSUER") != "" && os.Getenv("KEYCLOAK_TEST_USERS") != "" && os.Getenv("KEYCLOAK_CLI_CLIENT_ID") != "" {
		return true
	}
	return false
}

// IsOpenShiftCluster checks if the active cluster is OpenShift or a derivative
func IsOpenShiftCluster(ctx context.Context, c corev1client.NamespaceInterface) (bool, error) {
	switch _, err := c.Get(ctx, "openshift-controller-manager", metav1.GetOptions{}); {
	case err == nil:
		return true, nil
	case apierrors.IsNotFound(err):
		return false, nil
	default:
		return false, fmt.Errorf("unable to determine if we are running against an OpenShift cluster: %v", err)
	}
}
