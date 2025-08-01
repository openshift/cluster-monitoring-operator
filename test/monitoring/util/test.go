// Derived from code originally published in
//
//	https://github.com/openshift/openshift-tests-private
//
// at commit a6a189840b006da18c8203950983c0cee5ea7354.
package util

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubernetes/test/e2e/framework/testfiles"
	e2etestingmanifests "k8s.io/kubernetes/test/e2e/testing-manifests"
	testfixtures "k8s.io/kubernetes/test/fixtures"

	conformancetestdata "k8s.io/kubernetes/test/conformance/testdata"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

const (
	EnvIsExternalOIDCCluster = "ENV_IS_EXTERNAL_OIDC_CLUSTER"
	EnvIsKubernetesCluster   = "ENV_IS_KUBERNETES_CLUSTER"
)

var (
	reportFileName string
	quiet          bool
)

var TestContext *e2e.TestContextType = &e2e.TestContext

var (
	IsExternalOIDCClusterFlag = ""
	IsKubernetesClusterFlag   = ""
)

func InitStandardFlags() {
	e2e.RegisterCommonFlags(flag.CommandLine)
	e2e.RegisterClusterFlags(flag.CommandLine)

	// replaced by a bare import above.
	//e2e.RegisterStorageFlags()
}

// ProwGCPSetup makes sure certain required env vars are available in the case
// that extended tests are invoked directly via calls to ginkgo/extended.test
func InitDefaultEnvironmentVariables() {
	if ad := os.Getenv("ARTIFACT_DIR"); len(strings.TrimSpace(ad)) == 0 {
		os.Setenv("ARTIFACT_DIR", filepath.Join(os.TempDir(), "artifacts"))
	}
}

// checkSyntheticInput selects tests based on synthetic skips or focuses
func checkSyntheticInput() {
	checkSuiteSkips()
}

// TODO: Use either explicit tags (k8s.io) or https://github.com/onsi/ginkgo/v2/pull/228 to implement this.
// isPackage determines wether the test is in a package.  Ideally would be implemented in ginkgo.
func isPackage(pkg string) bool {
	return strings.Contains(ginkgo.CurrentSpecReport().FileName(), pkg)
}

// TODO: For both is*Test functions, use either explicit tags (k8s.io) or https://github.com/onsi/ginkgo/v2/pull/228
func isOriginTest() bool {
	return isPackage("/origin/test/")
}

func isKubernetesE2ETest() bool {
	return isPackage("/kubernetes/test/e2e/")
}

// checkSuiteSkips ensures Origin/Kubernetes synthetic skip labels are applied
// DEPRECATED: remove in a future release
func checkSuiteSkips() {
	suiteConfig, _ := ginkgo.GinkgoConfiguration()
	switch {
	case isOriginTest():
		skip := strings.Join(suiteConfig.SkipStrings, "|")
		if strings.Contains(skip, "Synthetic Origin") {
			ginkgo.Skip("skipping all openshift/origin tests")
		}
	case isKubernetesE2ETest():
		skip := strings.Join(suiteConfig.SkipStrings, "|")
		if strings.Contains(skip, "Synthetic Kubernetes") {
			ginkgo.Skip("skipping all k8s.io/kubernetes tests")
		}
	}
}

func InitTest(dryRun bool) error {
	InitDefaultEnvironmentVariables()
	// interpret synthetic input in `--ginkgo.focus` and/or `--ginkgo.skip`
	ginkgo.BeforeEach(checkSyntheticInput)

	TestContext.DeleteNamespace = os.Getenv("DELETE_NAMESPACE") != "false"
	TestContext.VerifyServiceAccount = true
	testfiles.AddFileSource(e2etestingmanifests.GetE2ETestingManifestsFS())
	testfiles.AddFileSource(testfixtures.GetTestFixturesFS())
	testfiles.AddFileSource(conformancetestdata.GetConformanceTestdataFS())
	TestContext.KubectlPath = "kubectl"
	TestContext.KubeConfig = KubeConfigPath()
	os.Setenv("KUBECONFIG", TestContext.KubeConfig)

	// "debian" is used when not set. At least GlusterFS tests need "custom".
	// (There is no option for "rhel" or "centos".)
	TestContext.NodeOSDistro = "custom"
	TestContext.MasterOSDistro = "custom"

	// load and set the host variable for kubectl
	if !dryRun {
		clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: TestContext.KubeConfig}, &clientcmd.ConfigOverrides{})
		cfg, err := clientConfig.ClientConfig()
		if err != nil {
			return err
		}
		TestContext.Host = cfg.Host
	}

	reportFileName = os.Getenv("TEST_REPORT_FILE_NAME")
	if reportFileName == "" {
		reportFileName = "junit"
	}

	quiet = os.Getenv("TEST_OUTPUT_QUIET") == "true"

	// Ensure that Kube tests run privileged (like they do upstream)
	// Not needed
	// TestContext.CreateTestingNS = createTestingNS

	// Not needed
	// klog.V(2).Infof("Extended test version %s", version.Get().String())
	return nil
}

func PreSetEnvK8s() (res string) {
	isK8s, err := PreDetermineK8sCluster()
	switch {
	case err != nil:
		res = "unknown"
	case isK8s:
		res = "yes"
	default:
		res = "no"
	}
	_ = os.Setenv(EnvIsKubernetesCluster, res)
	return res
}

func PreSetEnvOIDCCluster() (res string) {
	isOIDC, err := PreDetermineExternalOIDCCluster()
	switch {
	case err != nil:
		res = "unknown"
	case isOIDC:
		res = "yes"
	default:
		res = "no"
	}
	_ = os.Setenv(EnvIsExternalOIDCCluster, res)
	return res
}

// PreDetermineK8sCluster checks if the active cluster is a Kubernetes cluster (as opposed to OpenShift).
func PreDetermineK8sCluster() (isK8s bool, err error) {
	ctx := context.Background()

	kubeClient, err := e2e.LoadClientset(true)
	if err != nil {
		return false, fmt.Errorf("failed to load Kubernetes clientset: %w", err)
	}

	err = wait.PollUntilContextTimeout(ctx, 3*time.Second, 9*time.Second, true, func(ctx context.Context) (done bool, err error) {
		isOpenShift, isOCPErr := IsOpenShiftCluster(ctx, kubeClient.CoreV1().Namespaces())
		if isOCPErr != nil {
			e2e.Logf("failed to check if the active cluster is OpenShift: %v", isOCPErr)
			return false, nil
		}
		isK8s = !isOpenShift
		return true, nil
	})

	if err != nil {
		return false, fmt.Errorf("error during polling: %w", err)
	}

	return isK8s, nil
}

// PreDetermineExternalOIDCCluster checks if the cluster is using external OIDC preflight to avoid to check it everytime.
func PreDetermineExternalOIDCCluster() (bool, error) {

	clientConfig, err := e2e.LoadConfig(true)
	if err != nil {
		e2e.Logf("clientConfig err: %v", err)
		return false, err
	}
	client, err := configclient.NewForConfig(clientConfig)
	if err != nil {
		e2e.Logf("client err: %v", err)
		return false, err
	}

	var auth *configv1.Authentication
	var errAuth error
	err = wait.PollImmediate(3*time.Second, 9*time.Second, func() (bool, error) {
		auth, errAuth = client.ConfigV1().Authentications().Get(context.Background(), "cluster", metav1.GetOptions{})
		if errAuth != nil {
			e2e.Logf("auth err: %v", errAuth)
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		return false, errAuth
	}

	// auth.Spec.Type is optionial. if it does not exist, auth.Spec.Type is empty string
	// if it exists and set as "", it is also empty string
	e2e.Logf("Found authentication type used: %v", string(auth.Spec.Type))
	return string(auth.Spec.Type) == string(configv1.AuthenticationTypeOIDC), nil

	// keep it for possible usage
	// var out []byte
	// var err error
	// waitErr := wait.PollImmediate(3*time.Second, 9*time.Second, func() (bool, error) {
	// 	out, err = kubectlCmd("get", "authentication/cluster", "-o=jsonpath={.spec.type}").CombinedOutput()
	// 	if err != nil {
	// 		e2e.Logf("Fail to get the authentication/cluster, error: %v with %v, try again", err, string(out))
	// 		return false, nil
	// 	}
	// 	e2e.Logf("Found authentication type used: %v", string(out))
	// 	return true, nil
	// })
	// if waitErr != nil {
	// 	return false, fmt.Errorf("error checking if the cluster is using external OIDC: %v", string(out))
	// }

	// return string(out) == string(configv1.AuthenticationTypeOIDC), nil
}
