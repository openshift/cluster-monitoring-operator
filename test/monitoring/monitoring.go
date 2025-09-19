// Derived from code originally published in
//
//	https://github.com/openshift/openshift-tests-private
//
// at commit a6a189840b006da18c8203950983c0cee5ea7354.
package monitoring

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/cluster-monitoring-operator/test/monitoring/util"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

// NOTE: Please do not add new tests here. The goal is to merge Ginkgo tests into the E2E suite to get a single, unified testing framework.

func initProvider(provider string, dryRun bool) error {
	// Not needed
	// record the exit error to the output file
	// if err := decodeProviderTo(provider, exutil.TestContext, dryRun); err != nil {
	// 	e2e.Logf("Fail to decode Provider:%s, but continue to run with skeleton mode", provider)
	// }
	exutil.TestContext.AllowedNotReadyNodes = 100
	exutil.TestContext.MaxNodesToGather = 0
	// reale2e.SetViperConfig(os.Getenv("VIPERCONFIG"))

	// Not needed
	/* 	if err := initCSITests(dryRun); err != nil {
		return err
	} */

	// Not needed
	// exutil.AnnotateTestSuite()
	err := exutil.InitTest(dryRun)
	o.RegisterFailHandler(g.Fail)

	// TODO: infer SSH keys from the cluster
	return err
}

func checkClusterTypeAndSetEnvs() {
	if exutil.PreSetEnvK8s() == "yes" {
		_ = os.Setenv(exutil.EnvIsExternalOIDCCluster, "no")
	} else {
		exutil.PreSetEnvOIDCCluster()
	}
}

var _ = g.Describe("[sig-monitoring] Cluster_Observability parallel monitoring", func() {
	defer g.GinkgoRecover()

	// Some init taken for https://github.com/openshift/openshift-tests-private/blob/release-4.20/cmd/extended-platform-tests/openshift-tests.go
	err := initProvider("none", false)
	o.Expect(err).NotTo(o.HaveOccurred())
	checkClusterTypeAndSetEnvs()
	e2e.AfterReadingAllFlags(exutil.TestContext)
	e2e.TestContext.DumpLogsOnFailure = true
	exutil.TestContext.DumpLogsOnFailure = true

	var (
		oc                = exutil.NewCLI("monitor-"+getRandomString(), exutil.KubeConfigPath())
		monitoringCM      monitoringConfig
		monitoringBaseDir string
	)

	g.BeforeEach(func() {
		monitoringBaseDir = exutil.FixturePath("testdata", "monitoring")
		monitoringCMTemplate := filepath.Join(monitoringBaseDir, "cluster-monitoring-cm.yaml")
		// enable user workload monitoring and load other configurations from cluster-monitoring-config configmap
		monitoringCM = monitoringConfig{
			name:               "cluster-monitoring-config",
			namespace:          "openshift-monitoring",
			enableUserWorkload: true,
			template:           monitoringCMTemplate,
		}
		monitoringCM.create(oc)
	})

	// This test is already covered in test/e2e/config_test.go::TestClusterMonitorPrometheusK8Config
	// author: hongyli@redhat.com
	/* 	g.It("Author:hongyli-High-49073-Retention size settings for platform", func() {
		checkRetention(oc, "openshift-monitoring", "prometheus-k8s", "storage.tsdb.retention.size=10GiB", platformLoadTime)
		checkRetention(oc, "openshift-monitoring", "prometheus-k8s", "storage.tsdb.retention.time=45d", 20)
	}) */

	// TODO: could be merged with other RBAC tests
	// author: hongyli@redhat.com
	g.It("Author:hongyli-High-49514-federate service endpoint and route of platform Prometheus", func() {
		exutil.By("skip case for external OIDC cluster")
		isExternalOIDCCluster, err := exutil.IsExternalOIDCCluster(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if isExternalOIDCCluster {
			g.Skip("Skipping the test as we are running against an external OIDC cluster.")
		}

		exutil.By("Bind cluster-monitoring-view cluster role to current user")
		clusterRoleBindingName := "clusterMonitoringViewFederate"
		defer deleteClusterRoleBinding(oc, clusterRoleBindingName)
		clusterRoleBinding, err := bindClusterRoleToUser(oc, "cluster-monitoring-view", oc.Username(), clusterRoleBindingName)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("Created: %v %v", "ClusterRoleBinding", clusterRoleBinding.Name)

		exutil.By("Get token of current user")
		token := oc.UserConfig().BearerToken
		exutil.By("check federate endpoint service")
		checkMetric(oc, "https://prometheus-k8s.openshift-monitoring.svc:9091/federate --data-urlencode 'match[]=prometheus_build_info'", token, "prometheus_build_info", 3*platformLoadTime)

		exutil.By("check federate route")
		checkRoute(oc, "openshift-monitoring", "prometheus-k8s-federate", token, "match[]=prometheus_build_info", "prometheus_build_info", 3*platformLoadTime)
	})

	// This test is already covered in test/e2e/validatingwebhook_test.go::TestAlertManagerConfigValidatingWebhook
	// author: juzhao@redhat.com
	/* 	g.It("Author:juzhao-LEVEL0-Medium-49172-Enable validating webhook for AlertmanagerConfig customer resource", func() {
		var (
			err                       error
			output                    string
			namespace                 string
			invalidAlertmanagerConfig = filepath.Join(monitoringBaseDir, "invalid-alertmanagerconfig.yaml")
			validAlertmanagerConfig   = filepath.Join(monitoringBaseDir, "valid-alertmanagerconfig.yaml")
		)

		exutil.By("Get prometheus-operator-admission-webhook deployment")
		err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment", "prometheus-operator-admission-webhook", "-n", "openshift-monitoring").Execute()
		if err != nil {
			e2e.Logf("Unable to get deployment prometheus-operator-admission-webhook.")
		}
		o.Expect(err).NotTo(o.HaveOccurred())

		oc.SetupProject()
		namespace = oc.Namespace()

		exutil.By("confirm alertmanagerconfigs CRD exists")
		err = wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 180*time.Second, false, func(context.Context) (bool, error) {
			alertmanagerconfigs, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("customresourcedefinitions", "alertmanagerconfigs.monitoring.coreos.com").Output()
			if err != nil || strings.Contains(alertmanagerconfigs, "not found") {
				return false, nil
			}
			return true, nil
		})
		exutil.AssertWaitPollNoErr(err, "alertmanagerconfigs CRD does not exist")

		exutil.By("Create invalid AlertmanagerConfig, should throw out error")
		output, err = oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", invalidAlertmanagerConfig, "-n", namespace).Output()
		o.Expect(err).To(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("The AlertmanagerConfig \"invalid-test-config\" is invalid"))

		exutil.By("Create valid AlertmanagerConfig, should not have error")
		output, err = oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", validAlertmanagerConfig, "-n", namespace).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("valid-test-config created"))
	}) */

	// This test is already covered in test/e2e/alertmanager_test.go::TestAlertmanagerDataReplication
	//author: tagao@redhat.com
	/* 	g.It("Author:tagao-Medium-42800-Allow configuration of the log level for Alertmanager in the CMO configmap", func() {
		exutil.By("Check alertmanager container logs")
		exutil.WaitAndGetSpecificPodLogs(oc, "openshift-monitoring", "alertmanager", "alertmanager-main-0", "level=debug")
	}) */

	// author: juzhao@redhat.com
	g.It("Author:juzhao-Medium-43748-Ensure label namespace exists on all alerts", func() {
		exutil.By("Get token of SA prometheus-k8s")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

		exutil.By("check alerts, should have label namespace exists on all alerts")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="Watchdog"}'`, token, `"namespace":"openshift-monitoring"`, 2*platformLoadTime)
	})

	// This test is already covered in test/e2e/multi_namespace_test.go::TestMultinamespacePrometheusRule
	//author: tagao@redhat.com
	/* 	g.It("Author:tagao-Medium-47307-Add external label of origin to platform alerts", func() {
		exutil.By("Get token of SA prometheus-k8s")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

		exutil.By("check alerts, could see the `openshift_io_alert_source` field for in-cluster alerts")
		checkMetric(oc, "https://alertmanager-main.openshift-monitoring.svc:9094/api/v2/alerts", token, `"openshift_io_alert_source":"platform"`, 2*platformLoadTime)
	}) */

	//author: tagao@redhat.com
	g.It("Author:tagao-Medium-45163-Show labels for pods/nodes/namespaces/PV/PVC/PDB in metrics", func() {
		var (
			ns          string
			helloPodPvc = filepath.Join(monitoringBaseDir, "helloPodPvc.yaml")
		)
		exutil.By("Get token of SA prometheus-k8s")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

		exutil.By("check if the cluster have default storage class")
		checkSC, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("sc", "--no-headers").Output()
		e2e.Logf("storage class: %s", checkSC)
		hasSC := false
		if strings.Contains(checkSC, "default") {
			hasSC = true
			exutil.By("create project ns then attach pv/pvc")
			oc.SetupProject()
			ns = oc.Namespace()
			createResourceFromYaml(oc, ns, helloPodPvc)
		}

		exutil.By("Check labels for pod")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=kube_pod_labels{pod="alertmanager-main-0"}'`, token, `"label_statefulset_kubernetes_io_pod_name"`, uwmLoadTime)

		exutil.By("Check labels for node")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=kube_node_labels'`, token, `"label_kubernetes_io_hostname"`, uwmLoadTime)

		exutil.By("Check labels for namespace")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=kube_namespace_labels{namespace="openshift-monitoring"}'`, token, `"label_kubernetes_io_metadata_name"`, uwmLoadTime)

		exutil.By("Check labels for PDB")
		checkPDB, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pdb", "thanos-querier-pdb", "-n", "openshift-monitoring").Output()
		if !strings.Contains(checkPDB, `"thanos-querier-pdb" not found`) {
			checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=kube_poddisruptionbudget_labels{poddisruptionbudget="thanos-querier-pdb"}'`, token, `"label_app_kubernetes_io_name"`, uwmLoadTime)
		}

		exutil.By("Check labels for PV/PVC if need")
		if hasSC {
			checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=kube_persistentvolume_labels'`, token, `"persistentvolume"`, 2*uwmLoadTime)
			checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=kube_persistentvolumeclaim_labels'`, token, `"persistentvolumeclaim"`, 2*uwmLoadTime)
		}
	})

	// This test is already covered in test/e2e/config_test.go::TestClusterMonitorThanosQuerierConfig
	//author: tagao@redhat.com
	/* 	g.It("Author:tagao-Medium-48432-Allow OpenShift users to configure request logging for Thanos Querier query endpoint", func() {
		exutil.By("check thanos-querier pods are normal and able to see the request.logging-config setting")
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
		cmd := "-ojsonpath={.spec.template.spec.containers[?(@.name==\"thanos-query\")].args}"
		checkYamlconfig(oc, "openshift-monitoring", "deploy", "thanos-querier", cmd, "request.logging-config", true)

		//thanos-querier pod name will changed when cm modified, pods may not restart yet during the first check
		exutil.By("double confirm thanos-querier pods are ready")
		podList, err := exutil.GetAllPodsWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/instance=thanos-querier")
		o.Expect(err).NotTo(o.HaveOccurred())
		for _, pod := range podList {
			exutil.AssertPodToBeReady(oc, pod, "openshift-monitoring")
		}

		exutil.By("query with thanos-querier svc")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="Watchdog"}'`, token, `Watchdog`, 3*uwmLoadTime)

		exutil.By("check from thanos-querier logs")
		//oc -n openshift-monitoring logs -l app.kubernetes.io/instance=thanos-querier -c thanos-query --tail=-1
		checkLogWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/instance=thanos-querier", "thanos-query", `Watchdog`, true)
	}) */

	// This test is already covered in test/e2e/metrics_adapter_test.go::TestMetricsAPIAvailability
	// Also covered by the metrics API monitor test in origin
	// author: juzhao@redhat.com
	/* 	g.It("Author:juzhao-Low-43038-Should not have error for loading OpenAPI spec for v1beta1.metrics.k8s.io", func() {
		var (
			searchString string
			result       string
		)
		searchString = "loading OpenAPI spec for \"v1beta1.metrics.k8s.io\" failed with:"
		podList, err := exutil.GetAllPodsWithLabel(oc, "openshift-kube-apiserver", "app=openshift-kube-apiserver")
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("kube-apiserver Pods: %v", podList)

		exutil.By("check the kube-apiserver logs, should not have error for v1beta1.metrics.k8s.io")
		for _, pod := range podList {
			exutil.AssertPodToBeReady(oc, pod, "openshift-kube-apiserver")
			result, _ = exutil.GetSpecificPodLogs(oc, "openshift-kube-apiserver", "kube-apiserver", pod, searchString)
			e2e.Logf("output result in logs: %v", result)
			o.Expect(len(result) == 0).To(o.BeTrue(), "found the error logs which is unexpected")
		}
	}) */

	//author: tagao@redhat.com
	g.It("Author:tagao-Low-55670-Prometheus should not collecting error messages for completed pods [Serial]", func() {
		exutil.By("delete user-workload-monitoring-config/cluster-monitoring-config configmap at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check pod conditioning in openshift-kube-scheduler")
		podStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", "openshift-kube-scheduler").Output()
		e2e.Logf("kube-scheduler Pods:\n%s", podStatus)
		o.Expect(podStatus).To(o.ContainSubstring("Completed"))
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("check metrics-server pod logs")
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
		output, logsErr := oc.AsAdmin().WithoutNamespace().Run("logs").Args("-l", "app.kubernetes.io/name=metrics-server", "-c", "metrics-server", "--tail=-1", "-n", "openshift-monitoring").Output()
		o.Expect(logsErr).NotTo(o.HaveOccurred())
		if strings.Contains(output, "unable to fetch CPU metrics for pod openshift-kube-scheduler/") {
			e2e.Logf("output result in logs:\n%s", output)
			e2e.Failf("found unexpected logs")
		}
	})

	//author: tagao@redhat.com
	g.It("Author:tagao-LEVEL0-Medium-55767-Missing metrics in kube-state-metrics", func() {
		exutil.By("Get token of SA prometheus-k8s")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

		exutil.By("check kube-state-metrics metrics, the following metrics should be visible")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/label/__name__/values`, token, `"kube_pod_init_container_status_terminated_reason"`, uwmLoadTime)
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/label/__name__/values`, token, `"kube_pod_status_scheduled_time"`, uwmLoadTime)
	})

	// author: tagao@redhat.com
	g.It("Author:tagao-High-56168-PreChkUpgrade-NonPreRelease-Prometheus never sees endpoint propagation of a deleted pod", func() {
		var (
			ns          = "56168-upgrade-ns"
			exampleApp  = filepath.Join(monitoringBaseDir, "example-app.yaml")
			roleBinding = filepath.Join(monitoringBaseDir, "sa-prometheus-k8s-access.yaml")
		)
		exutil.By("Create example app")
		oc.AsAdmin().WithoutNamespace().Run("create").Args("namespace", ns).Execute()
		createResourceFromYaml(oc, ns, exampleApp)
		exutil.AssertAllPodsToBeReady(oc, ns)

		exutil.By("add role and role binding for example app")
		createResourceFromYaml(oc, ns, roleBinding)

		exutil.By("label namespace")
		oc.AsAdmin().WithoutNamespace().Run("label").Args("namespace", ns, "openshift.io/cluster-monitoring=true").Execute()

		exutil.By("check target is up")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/targets`, token, "up", 2*uwmLoadTime)
	})

	// author: tagao@redhat.com
	g.It("Author:tagao-High-56168-PstChkUpgrade-NonPreRelease-Prometheus never sees endpoint propagation of a deleted pod", func() {
		exutil.By("get the ns name in PreChkUpgrade")
		ns := "56168-upgrade-ns"

		exutil.By("delete related resource at the end of case")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", ns).Execute()

		exutil.By("delete example app deployment")
		deleteApp, _ := oc.AsAdmin().WithoutNamespace().Run("delete").Args("deploy", "prometheus-example-app", "-n", ns).Output()
		o.Expect(deleteApp).To(o.ContainSubstring(`"prometheus-example-app" deleted`))

		exutil.By("Get token of SA prometheus-k8s")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

		exutil.By("check metric up==0 under the test project, return null")
		checkMetric(oc, "https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=up{namespace=\"56168-upgrade-ns\"}==0'", token, `"result":[]`, 2*uwmLoadTime)

		exutil.By("check no alert 'TargetDown'")
		checkAlertNotExist(oc, "https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{namespace=\"56168-upgrade-ns\"}'", token, "TargetDown", uwmLoadTime)
	})

	// TODO: cound be merged with test/e2e/metrics_adapter_test.go::TestNodeMetricsPresence and test/e2e/metrics_adapter_test.go::TestPodMetricsPresence
	// author: tagao@redhat.com
	g.It("Author:tagao-LEVEL0-Medium-57254-oc adm top node/pod output should not give negative numbers", func() {
		exutil.By("check on node")
		checkNode, err := exec.Command("bash", "-c", `oc adm top node | awk '{print $2,$3,$4,$5}'`).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(checkNode).NotTo(o.ContainSubstring("-"))

		exutil.By("check on pod under specific namespace")
		checkNs, err := exec.Command("bash", "-c", `oc -n openshift-monitoring adm top pod | awk '{print $2,$3}'`).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(checkNs).NotTo(o.ContainSubstring("-"))
	})

	// TODO: could be merged with test/e2e/telemeter_test.go::TestTelemeterClient
	// author: tagao@redhat.com
	g.It("ConnectedOnly-Author:tagao-LEVEL0-Medium-55696-add telemeter alert TelemeterClientFailures", func() {
		exutil.By("check telemetry prometheusrule exists")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheusrules", "telemetry", "-n", "openshift-monitoring").Output()
		// Error from server (NotFound): prometheusrules.monitoring.coreos.com "telemetry" not found
		if strings.Contains(output, `"telemetry" not found`) {
			e2e.Logf("output: %s", output)
			g.Skip("this env does not have telemetry prometheusrule, skip the case")
		}

		exutil.By("check TelemeterClientFailures alert is added")
		output, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheusrules", "telemetry", "-ojsonpath={.spec.groups}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("TelemeterClientFailures"))
	})

	// author: juzhao@redhat.com
	g.It("Author:juzhao-Medium-62092-Don't fire NodeFilesystemAlmostOutOfSpace alert for certain tmpfs mount points", func() {
		exutil.By("check NodeFilesystemAlmostOutOfSpace alert from node-exporter-rules prometheusrules")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheusrules", "node-exporter-rules", `-ojsonpath={.spec.groups[*].rules[?(@.alert=="NodeFilesystemAlmostOutOfSpace")].expr}`, "-n", "openshift-monitoring").Output()
		e2e.Logf("NodeFilesystemAlmostOutOfSpace alert expr: %v", output)
		exutil.By("mountpoint /var/lib/ibmc-s3fs.* is excluded")
		o.Expect(output).To(o.ContainSubstring(`mountpoint!~"/var/lib/ibmc-s3fs.*"`))
	})

	// author: tagao@redhat.com
	g.It("Author:tagao-Medium-48350-create alert-routing-edit role to allow end users to manage alerting CR", func() {
		var (
			alertManagerConfig = filepath.Join(monitoringBaseDir, "valid-alertmanagerconfig.yaml")
		)
		exutil.By("skip case for external OIDC cluster")
		isExternalOIDCCluster, err := exutil.IsExternalOIDCCluster(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if isExternalOIDCCluster {
			g.Skip("Skipping the test as we are running against an external OIDC cluster.")
		}

		exutil.By("check clusterrole alert-routing-edit exists")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterrole").Output()
		o.Expect(strings.Contains(output, "alert-routing-edit")).To(o.BeTrue())

		exutil.By("create project, add alert-routing-edit RoleBinding to specific user")
		oc.SetupProject()
		ns := oc.Namespace()
		err = oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-role-to-user", "-n", ns, "alert-routing-edit", oc.Username()).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("create AlertmanagerConfig under the project")
		createResourceFromYaml(oc, ns, alertManagerConfig)

		exutil.By("check AlertmanagerConfig is created")
		output, _ = oc.WithoutNamespace().Run("get").Args("AlertmanagerConfig", "-n", ns).Output()
		o.Expect(output).To(o.ContainSubstring("valid-test-config"))

		exutil.By("the user should able to change AlertmanagerConfig")
		err = oc.WithoutNamespace().Run("patch").Args("AlertmanagerConfig", "valid-test-config", "-p", `{"spec":{"receivers":[{"name":"webhook","webhookConfigs":[{"url":"https://test.io/push"}]}]}}`, "--type=merge", "-n", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("check AlertmanagerConfig is updated")
		output, _ = oc.WithoutNamespace().Run("get").Args("AlertmanagerConfig", "valid-test-config", "-ojsonpath={.spec.receivers}", "-n", ns).Output()
		o.Expect(output).To(o.ContainSubstring("https://test.io/push"))

		exutil.By("the user should able to delete AlertmanagerConfig")
		err = oc.WithoutNamespace().Run("delete").Args("AlertmanagerConfig", "valid-test-config", "-n", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("check AlertmanagerConfig is deleted")
		output, _ = oc.WithoutNamespace().Run("get").Args("AlertmanagerConfig", "-n", ns).Output()
		o.Expect(output).NotTo(o.ContainSubstring("valid-test-config"))
	})

	// author: juzhao@redhat.com
	g.It("Author:juzhao-Low-62957-Prometheus and Alertmanager should configure ExternalURL correctly", func() {
		exutil.By("skip the case if there is not console operator enabled")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusteroperators", "console").Output()
		// Error from server (NotFound): clusteroperators.config.openshift.io "console" not found
		if strings.Contains(output, `"console" not found`) {
			e2e.Logf("output: %s", output)
			g.Skip("this cluster does not have console clusteroperator, skip the case")
		}

		exutil.By("get console route")
		consoleURL, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("route", "console", `-ojsonpath={.spec.host}`, "-n", "openshift-console").Output()
		e2e.Logf("console route is: %v", consoleURL)

		exutil.By("get externalUrl for alertmanager main")
		alertExternalUrl, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("alertmanager", "main", `-ojsonpath={.spec.externalUrl}`, "-n", "openshift-monitoring").Output()
		e2e.Logf("alertmanager main externalUrl is: %v", alertExternalUrl)
		o.Expect(alertExternalUrl).To(o.ContainSubstring("https://" + consoleURL))

		exutil.By("get externalUrl for prometheus k8s")
		prometheusExternalUrl, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheus", "k8s", `-ojsonpath={.spec.externalUrl}`, "-n", "openshift-monitoring").Output()
		e2e.Logf("prometheus k8s externalUrl is: %v", prometheusExternalUrl)
		o.Expect(prometheusExternalUrl).To(o.ContainSubstring("https://" + consoleURL))

		exutil.By("Get token of SA prometheus-k8s")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

		exutil.By("check from alertmanager API, the generatorURL should include https://${consoleURL}")
		checkMetric(oc, `https://alertmanager-main.openshift-monitoring.svc:9094/api/v2/alerts?&filter={alertname="Watchdog"}`, token, `"generatorURL":"https://`+consoleURL, 2*platformLoadTime)
	})

	// author: tagao@redhat.com
	g.It("Author:tagao-Medium-48942-validation for scrapeTimeout and relabel configs", func() {
		var (
			invalidServiceMonitor = filepath.Join(monitoringBaseDir, "invalid-ServiceMonitor.yaml")
		)
		exutil.By("delete test ServiceMonitor at the end of case")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("servicemonitor", "console-test-monitoring", "-n", "openshift-monitoring").Execute()

		exutil.By("create one ServiceMonitor, set scrapeTimeout bigger than scrapeInterval, and no targetLabel setting")
		createResourceFromYaml(oc, "openshift-monitoring", invalidServiceMonitor)

		exutil.By("able to see error in prometheus-operator logs")
		checkLogWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/name=prometheus-operator", "prometheus-operator", `scrapeTimeout \"120s\" greater than scrapeInterval \"30s\""`, true)

		exutil.By("check the configuration is not loaded to prometheus")
		checkPrometheusConfig(oc, "openshift-monitoring", "prometheus-k8s-0", `serviceMonitor/openshift-monitoring/console-test-monitoring/0`, false)

		exutil.By("edit ServiceMonitor, and set value for scrapeTimeout less than scrapeInterval")
		//oc patch servicemonitor console-test-monitoring --type='json' -p='[{"op": "replace", "path": "/spec/endpoints/0/scrapeTimeout", "value":"20s"}]' -n openshift-monitoring
		patchConfig := `[{"op": "replace", "path": "/spec/endpoints/0/scrapeTimeout", "value":"20s"}]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("servicemonitor", "console-test-monitoring", "-p", patchConfig, "--type=json", "-n", "openshift-monitoring").Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		exutil.By("able to see error for missing targetLabel in prometheus-operator logs")
		checkLogWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/name=prometheus-operator", "prometheus-operator", `relabel configuration for replace action needs targetLabel value`, true)

		exutil.By("add targetLabel to ServiceMonitor")
		//oc -n openshift-monitoring patch servicemonitor console-test-monitoring --type='json' -p='[{"op": "add", "path": "/spec/endpoints/0/relabelings/0/targetLabel", "value": "namespace"}]'
		patchConfig = `[{"op": "add", "path": "/spec/endpoints/0/relabelings/0/targetLabel", "value": "namespace"}]`
		patchErr = oc.AsAdmin().WithoutNamespace().Run("patch").Args("servicemonitor", "console-test-monitoring", "-p", patchConfig, "--type=json", "-n", "openshift-monitoring").Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		exutil.By("check the configuration loaded to prometheus")
		checkPrometheusConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "serviceMonitor/openshift-monitoring/console-test-monitoring/0", true)
	})

	// This test is already covered in test/e2e/alert_relabel_config_test.go::TestAlertRelabelConfig and test/e2e/alerting_rule_test.go::TestAlertingRule
	// author: juzhao@redhat.com
	/* 	g.It("Author:juzhao-Medium-62636-Graduate alert overrides and alert relabelings to GA", func() {
		var (
			alertingRule       = filepath.Join(monitoringBaseDir, "alertingRule.yaml")
			alertRelabelConfig = filepath.Join(monitoringBaseDir, "alertRelabelConfig.yaml")
		)
		exutil.By("delete the created AlertingRule/AlertRelabelConfig at the end of the case")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("AlertingRule", "monitoring-example", "-n", "openshift-monitoring").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("AlertRelabelConfig", "monitoring-watchdog", "-n", "openshift-monitoring").Execute()

		exutil.By("check AlertingRule/AlertRelabelConfig apiVersion is v1")
		_, explainErr := oc.WithoutNamespace().AsAdmin().Run("explain").Args("AlertingRule", "--api-version=monitoring.openshift.io/v1").Output()
		o.Expect(explainErr).NotTo(o.HaveOccurred())

		_, explainErr = oc.WithoutNamespace().AsAdmin().Run("explain").Args("AlertRelabelConfig", "--api-version=monitoring.openshift.io/v1").Output()
		o.Expect(explainErr).NotTo(o.HaveOccurred())

		exutil.By("create AlertingRule/AlertRelabelConfig under openshift-monitoring")
		createResourceFromYaml(oc, "openshift-monitoring", alertingRule)
		createResourceFromYaml(oc, "openshift-monitoring", alertRelabelConfig)

		exutil.By("check AlertingRule/AlertRelabelConfig are created")
		output, _ := oc.WithoutNamespace().Run("get").Args("AlertingRule/monitoring-example", "-ojsonpath={.metadata.name}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("monitoring-example"))
		output, _ = oc.WithoutNamespace().Run("get").Args("AlertRelabelConfig/monitoring-watchdog", "-ojsonpath={.metadata.name}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("monitoring-watchdog"))

		exutil.By("Get token of SA prometheus-k8s")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

		exutil.By("check the alert defined in AlertingRule could be found in thanos-querier API")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="ExampleAlert"}'`, token, `"alertname":"ExampleAlert"`, 2*platformLoadTime)

		exutil.By("Watchdog alert, the alert label is changed from \"severity\":\"none\" to \"severity\":\"critical\" in alertmanager API")
		checkMetric(oc, `https://alertmanager-main.openshift-monitoring.svc:9094/api/v2/alerts?&filter={alertname="Watchdog"}`, token, `"severity":"critical"`, 2*platformLoadTime)
	}) */

	// TODO: could be merged with test/e2e/node_exporter_test.go::TestNodeExporterCollectorDisablement
	// author: tagao@redhat.com
	g.It("Author:tagao-Low-67008-node-exporter: disable btrfs collector", func() {
		exutil.By("Get token of SA prometheus-k8s")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

		exutil.By("should not see btrfs collector related metrics")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="btrfs"}'`, token, "\"result\":[]", uwmLoadTime)

		exutil.By("check btrfs collector is disabled by default")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("no-collector.btrfs"))
	})

	// author: tagao@redhat.com
	g.It("Author:tagao-LEVEL0-Medium-68292-Limit the value of GOMAXPROCS on node-exporter to 4", func() {
		exutil.By("check the gomaxprocs value in logs")
		// % oc -n openshift-monitoring logs -l app.kubernetes.io/name=node-exporter --tail=-1 -c node-exporter | grep -o 'gomaxprocs=[0-9]*' | uniq | cut -d= -f2
		nodeExporterLogs, errLogs := oc.AsAdmin().WithoutNamespace().Run("logs").Args("-l", "app.kubernetes.io/name=node-exporter", "--tail=-1", "-c", "node-exporter", "-n", "openshift-monitoring").OutputToFile("OCP-68292_nodeExporter.log")
		o.Expect(errLogs).NotTo(o.HaveOccurred())
		cmd := fmt.Sprintf(`cat %v | grep -o '%s' | uniq | cut -d= -f2`, nodeExporterLogs, "gomaxprocs=[0-9]*")
		gomaxprocsValue, err := exec.Command("bash", "-c", cmd).Output()
		e2e.Logf("gomaxprocsValue output: %s", gomaxprocsValue)
		gomaxprocsNum, _ := strconv.Atoi(string(gomaxprocsValue))
		o.Expect(gomaxprocsNum).To(o.BeNumerically("<=", 4))
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	// TODO: could be merged with test/e2e/node_exporter_test.go::TestNodeExporterNetworkDevicesExclusion
	// author: juzhao@redhat.com
	g.It("Author:juzhao-Low-68958-node_exporter shouldn't collect metrics for Calico Virtual NICs", func() {
		exutil.By("Get token of SA prometheus-k8s")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

		exutil.By("should not see metrics for Calico Virtual NICs")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_network_info{device=~"cali.*"}'`, token, "\"result\":[]", uwmLoadTime)
	})

	// author: tagao@redhat.com
	g.It("Author:tagao-Medium-69087-Replace OAuth-proxy container with kube-rbac-proxy in Thanos-Querier pod", func() {
		exutil.By("skip case for external OIDC cluster")
		isExternalOIDCCluster, err := exutil.IsExternalOIDCCluster(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if isExternalOIDCCluster {
			g.Skip("Skipping the test as we are running against an external OIDC cluster.")
		}

		exutil.By("check role added")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("role", "cluster-monitoring-metrics-api", "-n", "openshift-monitoring").Output()
		o.Expect(output).NotTo(o.ContainSubstring("NotFound"))
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("check cluster role added")
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterRole", "cluster-monitoring-view", "-ojsonpath={.rules}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("monitoring.coreos.com"))
		o.Expect(err).NotTo(o.HaveOccurred())
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterRole", "prometheus-k8s", "-ojsonpath={.rules[?(\"monitoring.coreos.com\")]}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("monitoring.coreos.com"))
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("check thanos-querier deployment")
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deploy", "thanos-querier", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"kube-rbac-proxy-web\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("kube-rbac-proxy/config.yaml"))
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("check thanos-querier secret")
		// should see `thanos-querier-kube-rbac-proxy-web` is added, and `thanos-querier-oauth-cookie` is removed
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", "thanos-querier-kube-rbac-proxy-web", "-n", "openshift-monitoring").Output()
		o.Expect(output).NotTo(o.ContainSubstring("NotFound"))
		o.Expect(err).NotTo(o.HaveOccurred())
		output, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", "thanos-querier-oauth-cookie", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("NotFound"))

		exutil.By("Get token of current user")
		token := oc.UserConfig().BearerToken

		exutil.By("Get route of thanos-querier")
		host, hostErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("route", "thanos-querier", "-ojsonpath={.spec.host}", "-n", "openshift-monitoring").Output()
		o.Expect(hostErr).NotTo(o.HaveOccurred())

		exutil.By("test role can NOT access to ThanosQuerier")
		// % curl -H "Authorization: Bearer $token" -k "https://$host/api/v1/query?" --data-urlencode 'query=up{namespace="openshift-monitoring"}'
		checkMetric(oc, "https://"+host+"/api/v1/query? --data-urlencode 'query=up{namespace=\"openshift-monitoring\"}'", token, "Forbidden", 2*platformLoadTime)

		exutil.By("add role access to ThanosQuerier")
		admErr := oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-role-to-user", "--role-namespace=openshift-monitoring", "-n", "openshift-monitoring", "cluster-monitoring-metrics-api", oc.Username()).Execute()
		o.Expect(admErr).NotTo(o.HaveOccurred())

		exutil.By("test role access to ThanosQuerier")
		// % curl -H "Authorization: Bearer $token" -k "https://$host/api/v1/query?" --data-urlencode 'query=up{namespace="openshift-monitoring"}'
		checkMetric(oc, "https://"+host+"/api/v1/query? --data-urlencode 'query=up{namespace=\"openshift-monitoring\"}'", token, "up", 2*platformLoadTime)
	})

	// This test is already covered in test/e2e/config_test.go::TestClusterMonitorPrometheusK8Config
	// author: juzhao@redhat.com
	/* 	g.It("Author:juzhao-Medium-69924-Set scrape.timestamp tolerance for prometheus", func() {
		exutil.By("confirm in-cluster prometheus is created")
		err := wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 180*time.Second, false, func(context.Context) (bool, error) {
			prometheus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheus", "k8s", "-n", "openshift-monitoring").Output()
			if err != nil || strings.Contains(prometheus, "not found") {
				return false, nil
			}
			return true, nil
		})
		exutil.AssertWaitPollNoErr(err, "in-cluster prometheus is not created")

		exutil.By("check in-cluster prometheus scrape.timestamp tolerance")
		cmd := `-ojsonpath={.spec.additionalArgs[?(@.name=="scrape.timestamp-tolerance")]}`
		checkYamlconfig(oc, "openshift-monitoring", "prometheus", "k8s", cmd, `"value":"15ms"`, true)

		//check settings in prometheus pods
		podNames, err := exutil.GetAllPodsWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/name=prometheus")
		o.Expect(err).NotTo(o.HaveOccurred())
		for _, pod := range podNames {
			cmd := "-ojsonpath={.spec.containers[?(@.name==\"prometheus\")].args}"
			checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, `--scrape.timestamp-tolerance=15ms`, true)
		}
	}) */

	// author: juzhao@redhat.com
	g.It("Author:juzhao-Medium-70051-Adjust NodeClock alerting rules to be inactive when the PTP operator is installed", func() {
		exutil.By("check NodeClockSkewDetected alert expr")
		cmd := "-ojsonpath={.spec.groups[*].rules[?(@.alert==\"NodeClockSkewDetected\")].expr}"
		checkYamlconfig(oc, "openshift-monitoring", "prometheusrules", "node-exporter-rules", cmd, `absent(up{job="ptp-monitor-service"})`, true)

		exutil.By("check NodeClockNotSynchronising alert expr")
		cmd = "-ojsonpath={.spec.groups[*].rules[?(@.alert==\"NodeClockNotSynchronising\")].expr}"
		checkYamlconfig(oc, "openshift-monitoring", "prometheusrules", "node-exporter-rules", cmd, `absent(up{job="ptp-monitor-service"})`, true)
	})

	// TODO: could be merged with other RBAC tests
	// author: juzhao@redhat.com
	g.It("Author:juzhao-Medium-69927-Allow to query alerts of application namespaces as an application user from command line", func() {
		exutil.By("skip case for external OIDC cluster")
		isExternalOIDCCluster, err := exutil.IsExternalOIDCCluster(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if isExternalOIDCCluster {
			g.Skip("Skipping the test as we are running against an external OIDC cluster.")
		}

		_, err = oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-cluster-role-to-user", "cluster-admin", oc.Username()).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "remove-cluster-role-from-user", "cluster-admin", oc.Username()).Execute()

		podNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", "openshift-monitoring", "-l", "app.kubernetes.io/name=prometheus", "--ignore-not-found", "-o=jsonpath={.items[*].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		// double check prometheus pods are Running
		for _, pod := range strings.Fields(podNames) {
			assertPodToBeReady(oc, pod, "openshift-monitoring")
		}

		podNames, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", "openshift-monitoring", "-l", "app.kubernetes.io/name=thanos-query", "--ignore-not-found", "-o=jsonpath={.items[*].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		// double check thanos-querier pods are Running
		for _, pod := range strings.Fields(podNames) {
			assertPodToBeReady(oc, pod, "openshift-monitoring")
		}

		exutil.By("get user API token")
		token, _ := oc.Run("whoami").Args("-t").Output()

		exutil.By("Run port-forward command")
		cmd, _, _, err := oc.AsAdmin().WithoutNamespace().Run("port-forward").Args("-n", "openshift-monitoring", "service/thanos-querier", "9093:9093").Background()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer cmd.Process.Kill()
		output, err := exec.Command("bash", "-c", "ps -ef | grep 9093").Output()
		e2e.Logf("output is: %s", output)
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("curl without namespace parameter should return Bad Request")
		curlcmd := "curl -G -k -s -H \"Authorization:Bearer " + token + "\" " + "https://127.0.0.1:9093/api/v1/alerts"
		err = wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 30*time.Second, false, func(context.Context) (bool, error) {
			output, err := exec.Command("bash", "-c", curlcmd).Output()
			e2e.Logf("output is: %s", output)
			if err != nil {
				e2e.Logf("failed to execute the curl: %s. Trying again", err)
				return false, nil
			}
			if matched, _ := regexp.MatchString("Bad Request", string(output)); matched {
				e2e.Logf("Bad Request. The request or configuration is malformed\n")
				return true, nil
			}
			return false, nil
		})
		exutil.AssertWaitPollNoErr(err, "failed to curl without namespace parameter")

		exutil.By("curl with namespace parameter should return alerts")
		err = wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 30*time.Second, false, func(context.Context) (bool, error) {
			output, err := exec.Command("bash", "-c", curlcmd+"?namespace=openshift-monitoring").Output()
			e2e.Logf("output is: %s", output)
			if err != nil {
				e2e.Logf("failed to execute the curl: %s. Trying again", err)
				return false, nil
			}
			if matched, _ := regexp.MatchString(`"alertname":"Watchdog"`, string(output)); matched {
				e2e.Logf("curl with namespace parameter returns Watchdog alert\n")
				return true, nil
			}
			return false, nil
		})
		exutil.AssertWaitPollNoErr(err, "Cannot get result with namespace parameter")
	})

	// TODO: could be merged with other RBAC tests
	// author: tagao@redhat.com
	g.It("Author:tagao-Medium-69195-Replace OAuth-proxy container with Kube-RBAC-proxy in Prometheus pod", func() {
		exutil.By("skip case for external OIDC cluster")
		isExternalOIDCCluster, err := exutil.IsExternalOIDCCluster(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if isExternalOIDCCluster {
			g.Skip("Skipping the test as we are running against an external OIDC cluster.")
		}

		exutil.By("check prometheus-k8s-kube-rbac-proxy-web added")
		checkSecret, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", "prometheus-k8s-kube-rbac-proxy-web", "-n", "openshift-monitoring").Output()
		o.Expect(checkSecret).NotTo(o.ContainSubstring("not found"))

		exutil.By("check secret prometheus-k8s-proxy removed")
		checkSecret, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", "prometheus-k8s-proxy", "-n", "openshift-monitoring").Output()
		o.Expect(checkSecret).To(o.ContainSubstring("not found"))

		exutil.By("check prometheus k8s configs, kube-rbac-proxy-web related configs should exist")
		checkPrometheusK8s, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheus", "k8s", "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy-web\")].ports}", "-n", "openshift-monitoring").Output()
		o.Expect(checkPrometheusK8s).To(o.ContainSubstring("9091"))
		o.Expect(checkPrometheusK8s).To(o.ContainSubstring("web"))
		checkPrometheusK8s, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheus", "k8s", "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy-web\")].volumeMounts}", "-n", "openshift-monitoring").Output()
		o.Expect(checkPrometheusK8s).To(o.ContainSubstring("secret-prometheus-k8s-kube-rbac-proxy-web"))
		checkPrometheusK8s, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheus", "k8s", "-ojsonpath={.spec.secrets}", "-n", "openshift-monitoring").Output()
		o.Expect(checkPrometheusK8s).To(o.ContainSubstring("prometheus-k8s-kube-rbac-proxy-web"))

		exutil.By("check prometheus k8s pods, prometheus-proxy container is removed")
		checkPO, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "prometheus-k8s-0", "-ojsonpath={.spec.containers[*].name}", "-n", "openshift-monitoring").Output()
		o.Expect(checkPO).NotTo(o.ContainSubstring("prometheus-proxy"))

		exutil.By("check prometheus-k8s servicemonitor, port should be keep at metrics")
		checkSM, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("ServiceMonitor", "prometheus-k8s", "-ojsonpath={.spec.endpoints[]}", "-n", "openshift-monitoring").Output()
		o.Expect(checkSM).To(o.ContainSubstring(`"port":"metrics"`))

		exutil.By("check telemeter-client deploy")
		checkTL, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("deploy", "telemeter-client", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"telemeter-client\")].env[?(@.name==\"FROM\")]}", "-n", "openshift-monitoring").Output()
		if !strings.Contains(checkTL, `"telemeter-client" not found`) {
			o.Expect(checkTL).To(o.ContainSubstring(`"value":"https://prometheus-k8s.openshift-monitoring.svc:9091"`))
		}

		exutil.By("check secret thanos-querier-kube-rbac-proxy-metrics")
		checkSecret, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", "thanos-querier-kube-rbac-proxy-metrics", "-ojsonpath={.metadata.labels}", "-n", "openshift-monitoring").Output()
		o.Expect(checkSecret).To(o.ContainSubstring(`"app.kubernetes.io/component":"query-layer"`))
		o.Expect(checkSecret).To(o.ContainSubstring(`"app.kubernetes.io/instance":"thanos-querier"`))

		exutil.By("check secret thanos-querier-kube-rbac-proxy-web")
		checkSecret, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", "thanos-querier-kube-rbac-proxy-web", "-ojsonpath={.metadata.labels}", "-n", "openshift-monitoring").Output()
		o.Expect(checkSecret).To(o.ContainSubstring(`"app.kubernetes.io/component":"query-layer"`))
		o.Expect(checkSecret).To(o.ContainSubstring(`"app.kubernetes.io/instance":"thanos-querier"`))

		exutil.By("test role access to prometheus-k8s")
		exutil.By("Get token of current user")
		token := oc.UserConfig().BearerToken

		exutil.By("Get route of prometheus-k8s")
		host, hostErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("route", "prometheus-k8s", "-ojsonpath={.spec.host}", "-n", "openshift-monitoring").Output()
		o.Expect(hostErr).NotTo(o.HaveOccurred())

		exutil.By("test role can NOT access to prometheus-k8s")
		// % curl -H "Authorization: Bearer $token" -k "https://$host/api/v1/query?" --data-urlencode 'query=up{namespace="openshift-monitoring"}'
		checkMetric(oc, "https://"+host+"/api/v1/query? --data-urlencode 'query=up{namespace=\"openshift-monitoring\"}'", token, "Forbidden", 2*platformLoadTime)

		exutil.By("add role access to prometheus-k8s")
		admErr := oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-role-to-user", "--role-namespace=openshift-monitoring", "-n", "openshift-monitoring", "cluster-monitoring-metrics-api", oc.Username()).Execute()
		o.Expect(admErr).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "remove-role-from-user", "--role-namespace=openshift-monitoring", "-n", "openshift-monitoring", "cluster-monitoring-metrics-api", oc.Username()).Execute()

		exutil.By("test role access to prometheus-k8s")
		// % curl -H "Authorization: Bearer $token" -k "https://$host/api/v1/query?" --data-urlencode 'query=up{namespace="openshift-monitoring"}'
		checkMetric(oc, "https://"+host+"/api/v1/query? --data-urlencode 'query=up{namespace=\"openshift-monitoring\"}'", token, "up", 2*platformLoadTime)
	})

	// TODO: could be merged with other RBAC tests
	// author: tagao@redhat.com
	g.It("Author:tagao-Medium-72560-Replace oauth-proxy container with kube-rbac-proxy in Alertmanager pods", func() {
		exutil.By("skip case for external OIDC cluster")
		isExternalOIDCCluster, err := exutil.IsExternalOIDCCluster(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if isExternalOIDCCluster {
			g.Skip("Skipping the test as we are running against an external OIDC cluster.")
		}

		exutil.By("check new configs added to alertmanager main")
		checkAlertmanager, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("alertmanager", "main", "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy-web\")]}", "-n", "openshift-monitoring").Output()
		o.Expect(checkAlertmanager).To(o.ContainSubstring(`"--secure-listen-address=0.0.0.0:9095"`))
		o.Expect(checkAlertmanager).To(o.ContainSubstring(`"--upstream=http://127.0.0.1:9093"`))
		o.Expect(checkAlertmanager).To(o.ContainSubstring(`"--config-file=/etc/kube-rbac-proxy/config.yaml"`))
		o.Expect(checkAlertmanager).To(o.ContainSubstring(`"name":"kube-rbac-proxy-web"`))
		o.Expect(checkAlertmanager).To(o.ContainSubstring(`"mountPath":"/etc/kube-rbac-proxy"`))
		o.Expect(checkAlertmanager).To(o.ContainSubstring(`"name":"secret-alertmanager-kube-rbac-proxy-web"`))

		exutil.By("check new secret added and old one removed")
		checkSecret, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", "alertmanager-kube-rbac-proxy-web", "-n", "openshift-monitoring").Output()
		o.Expect(checkSecret).NotTo(o.ContainSubstring("not found"))
		checkSecret, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", "alertmanager-main-proxy", "-n", "openshift-monitoring").Output()
		o.Expect(checkSecret).To(o.ContainSubstring("not found"))

		exutil.By("check alertmanager pods, alertmanager-proxy container is removed")
		checkPO, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "alertmanager-main-0", "-ojsonpath={.spec.containers[*].name}", "-n", "openshift-monitoring").Output()
		o.Expect(checkPO).NotTo(o.ContainSubstring("alertmanager-proxy"))

		exutil.By("check role, monitoring-alertmanager-edit add new resourceNames")
		checkRole, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("role", "monitoring-alertmanager-edit", "-ojsonpath={.rules}", "-n", "openshift-monitoring").Output()
		o.Expect(checkRole).To(o.ContainSubstring(`"resourceNames":["main"]`))
		o.Expect(checkRole).To(o.ContainSubstring(`"resources":["alertmanagers/api"]`))
		o.Expect(checkRole).To(o.ContainSubstring(`"verbs":["*"]`))

		exutil.By("test user access to alertmanager")
		exutil.By("Get token of current user")
		token := oc.UserConfig().BearerToken

		exutil.By("Get route of alertmanager-main")
		host, hostErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("route", "alertmanager-main", "-ojsonpath={.spec.host}", "-n", "openshift-monitoring").Output()
		o.Expect(hostErr).NotTo(o.HaveOccurred())

		exutil.By("test role can NOT access to alertmanager")
		// % curl -H "Authorization: Bearer $TOKEN" -k "https://$HOST/api/v2/receivers"
		checkMetric(oc, "https://"+host+"/api/v2/receivers", token, "Forbidden", 2*platformLoadTime)

		exutil.By("add role access to alertmanager")
		admErr := oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-role-to-user", "--role-namespace=openshift-monitoring", "-n", "openshift-monitoring", "monitoring-alertmanager-edit", oc.Username()).Execute()
		o.Expect(admErr).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "remove-role-from-user", "--role-namespace=openshift-monitoring", "-n", "openshift-monitoring", "monitoring-alertmanager-edit", oc.Username()).Execute()

		exutil.By("test role access to alertmanager")
		// % curl -H "Authorization: Bearer $TOKEN" -k "https://$HOST/api/v2/receivers"
		checkMetric(oc, "https://"+host+"/api/v2/receivers", token, `"name":"Watchdog"`, 2*platformLoadTime)
	})

	// TODO: could be merged with other RBAC tests
	// author: juzhao@redhat.com
	g.It("Author:juzhao-Medium-73294-add role.rbac.authorization.k8s.io/monitoring-alertmanager-view", func() {
		exutil.By("skip case for external OIDC cluster")
		isExternalOIDCCluster, err := exutil.IsExternalOIDCCluster(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if isExternalOIDCCluster {
			g.Skip("Skipping the test as we are running against an external OIDC cluster.")
		}

		exutil.By("Check monitoring-alertmanager-view role is created")
		err = oc.AsAdmin().WithoutNamespace().Run("get").Args("role", "monitoring-alertmanager-view", "-n", "openshift-monitoring").Execute()
		if err != nil {
			e2e.Logf("Unable to get role monitoring-alertmanager-view.")
		}
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("Bind monitoring-alertmanager-view role to user")
		admErr := oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-role-to-user", "--role-namespace=openshift-monitoring", "-n", "openshift-monitoring", "monitoring-alertmanager-view", oc.Username()).Execute()
		o.Expect(admErr).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "remove-role-from-user", "--role-namespace=openshift-monitoring", "-n", "openshift-monitoring", "monitoring-alertmanager-view", oc.Username()).Execute()

		exutil.By("Get alertmanager-main route")
		host, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("route", "alertmanager-main", "-ojsonpath={.spec.host}", "-n", "openshift-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("Get token of current user")
		token := oc.UserConfig().BearerToken

		exutil.By("Check monitoring-alertmanager-view role can view receivers and alerts API")
		checkMetric(oc, "https://"+host+"/api/v2/receivers", token, "Watchdog", 2*platformLoadTime)
		checkMetric(oc, "https://"+host+"/api/v2/alerts?&filter={alertname=\"Watchdog\"}", token, "Watchdog", 2*platformLoadTime)

		exutil.By("Check monitoring-alertmanager-view role can not silence alert")
		currentTime := time.Now()
		start := time.Now().UTC().Format("2006-01-02T15:04:05Z")
		twoHoursLater := currentTime.Add(2 * time.Hour)
		end := twoHoursLater.UTC().Format("2006-01-02T15:04:05Z")
		// % curl -k -H "Authorization: Bearer $token" -X POST -d '{"matchers":[{"name":"alertname","value":"Watchdog"}],"startsAt":"'"$start"'","endsAt":"'"$end"'","createdBy":"testuser","comment":"Silence Watchdog alert"}' https://$HOST/api/v2/silences
		curlCmd := `curl -k -H "Authorization: Bearer ` + token + `" -X POST -d '{"matchers":[{"name":"alertname","value":"Watchdog"}],"startsAt":"` + start + `","endsAt":"` + end + `","createdBy":"testuser","comment":"Silence Watchdog alert"}' "https://` + host + `/api/v2/silences"`
		out, err := exec.Command("bash", "-c", curlCmd).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(string(out), "Forbidden")).Should(o.BeTrue())
	})

	// TODO: could be merged with test/e2e/metrics_adapter_test.go::TestMetricsServerRollout
	// author: juzhao@redhat.com
	g.It("Author:juzhao-Medium-73288-Enable request headers flags for metrics server", func() {
		exutil.By("Check metrics-server deployment exists")
		err := oc.AsAdmin().WithoutNamespace().Run("get").Args("deploy", "metrics-server", "-n", "openshift-monitoring").Execute()
		if err != nil {
			e2e.Logf("Unable to find metrics-server deployment.")
		}
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("Check request headers flags for metrics server")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("deploy/metrics-server", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"metrics-server\")].args}", "-n", "openshift-monitoring").Output()
		params := []string{"requestheader-client-ca-file", "requestheader-allowed-names", "requestheader-extra-headers-prefix", "requestheader-group-headers", "requestheader-username-headers"}
		for _, param := range params {
			o.Expect(output).To(o.ContainSubstring(param))
		}
	})

	// author: juzhao@redhat.com
	g.It("Author:juzhao-NonHyperShiftHOST-Medium-81507-add topology signal for telemeter", func() {
		exutil.By("make sure telemeter-client deployment exists")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("deploy", "telemeter-client", "-n", "openshift-monitoring").Output()
		if strings.Contains(output, `"telemeter-client" not found`) {
			g.Skip("The cluster does not have telemeter-client deployment, skip the case")
		}

		exutil.By("check cluster:controlplane_topology:info and cluster:infrastructure_topology:info are added to telemeter-client deployment")
		output, err := oc.AsAdmin().Run("get").Args("deployment", "telemeter-client", "-n", "openshift-monitoring", "-ojsonpath={.spec.template.spec.containers[*].command}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("cluster:controlplane_topology:info"))
		o.Expect(output).To(o.ContainSubstring("cluster:infrastructure_topology:info"))

		exutil.By("check result for cluster:infrastructure_topology:info metric is the same with infrastructure status.infrastructureTopology")
		cmd := "-ojsonpath={.status.infrastructureTopology}"
		infrastructureTopology, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", cmd).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("infrastructureTopology is: %v", infrastructureTopology)
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=cluster:infrastructure_topology:info'`, token, `"mode":"`+infrastructureTopology+`"`, 2*uwmLoadTime)

		exutil.By("check result for cluster:controlplane_topology:info metric is the same with infrastructure status.controlPlaneTopology")
		cmd = "-ojsonpath={.status.controlPlaneTopology}"
		controlPlaneTopology, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", cmd).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("controlPlaneTopology is: %v", controlPlaneTopology)
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=cluster:controlplane_topology:info'`, token, `"mode":"`+controlPlaneTopology+`"`, 2*uwmLoadTime)
	})

	g.Context("user workload monitoring", func() {
		var (
			uwmMonitoringConfig string
		)
		g.BeforeEach(func() {
			monitoringBaseDir = exutil.FixturePath("testdata", "monitoring")
			uwmMonitoringConfig = filepath.Join(monitoringBaseDir, "uwm-monitoring-cm.yaml")
			createUWMConfig(oc, uwmMonitoringConfig)
		})

		g.When("Need example app", func() {
			var (
				ns         string
				exampleApp string
			)
			g.BeforeEach(func() {
				exampleApp = filepath.Join(monitoringBaseDir, "example-app.yaml")
				//create project
				oc.SetupProject()
				ns = oc.Namespace()
				//create example app and alert rule under the project
				exutil.By("Create example app!")
				createResourceFromYaml(oc, ns, exampleApp)
				exutil.AssertAllPodsToBeReady(oc, ns)
			})

			// This test is already covered in test/e2e/user_workload_monitoring_test.go::TestUserWorkloadMonitoringOptOut
			// author: hongyli@redhat.com
			/* 			g.It("Author:hongyli-Critical-43341-Exclude namespaces from user workload monitoring based on label", func() {
				var (
					exampleAppRule = filepath.Join(monitoringBaseDir, "example-alert-rule.yaml")
				)

				exutil.By("label project not being monitored")
				labelNameSpace(oc, ns, "openshift.io/user-monitoring=false")

				exutil.By("make sure the namespace is labeled with openshift.io/user-monitoring=false")
				result, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("namespace", ns, "-ojsonpath={.metadata.labels}").Output()
				if err != nil {
					o.Expect(result).To(o.ContainSubstring(`"openshift.io/user-monitoring":"false"`))
				}
				if !strings.Contains(result, `"openshift.io/user-monitoring":"false"`) {
					e2e.Logf("namespace %s does not have openshift.io/user-monitoring=false label, relabel it again", ns)
					labelNameSpace(oc, ns, "openshift.io/user-monitoring=false")
				}

				//create example app and alert rule under the project
				exutil.By("Create example alert rule!")
				createResourceFromYaml(oc, ns, exampleAppRule)

				exutil.By("Get token of SA prometheus-k8s")
				token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

				exutil.By("check metrics")
				checkMetric(oc, "https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=version{namespace=\""+ns+"\"}'", token, "\"result\":[]", 2*uwmLoadTime)
				exutil.By("check alerts")
				checkMetric(oc, "https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{namespace=\""+ns+"\"}'", token, "\"result\":[]", 2*uwmLoadTime)

				exutil.By("label project being monitored")
				labelNameSpace(oc, ns, "openshift.io/user-monitoring=true")

				exutil.By("check metrics")
				checkMetric(oc, "https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=version{namespace=\""+ns+"\"}'", token, "prometheus-example-app", 2*uwmLoadTime)

				exutil.By("check alerts")
				checkMetric(oc, "https://thanos-ruler.openshift-user-workload-monitoring.svc:9091/api/v1/alerts", token, "TestAlert", 2*uwmLoadTime)
			}) */

			// TODO: could be merged with other RBAC tests
			// author: hongyli@redhat.com
			g.It("Author:hongyli-High-50024-High-49515-Check federate route and service of user workload Prometheus", func() {
				var err error
				exutil.By("Bind cluster-monitoring-view RBAC to default service account")
				uwmFederateRBACViewName := "uwm-federate-rbac-" + ns
				defer deleteBindMonitoringViewRoleToDefaultSA(oc, uwmFederateRBACViewName)
				clusterRoleBinding, err := bindMonitoringViewRoleToDefaultSA(oc, ns, uwmFederateRBACViewName)
				o.Expect(err).NotTo(o.HaveOccurred())
				e2e.Logf("Created: %v %v", "ClusterRoleBinding", clusterRoleBinding.Name)
				exutil.By("Get token of default service account")
				token := getSAToken(oc, "default", ns)

				exutil.By("check uwm federate endpoint service")
				checkMetric(oc, "https://prometheus-user-workload.openshift-user-workload-monitoring.svc:9092/federate --data-urlencode 'match[]=version'", token, "prometheus-example-app", 2*uwmLoadTime)

				exutil.By("check uwm federate route")
				checkRoute(oc, "openshift-user-workload-monitoring", "federate", token, "match[]=version", "prometheus-example-app", 100)

			})

			// author: tagao@redhat.com
			g.It("Author:tagao-Medium-50241-Prometheus (uwm) externalLabels not showing always in alerts", func() {
				var (
					exampleAppRule = filepath.Join(monitoringBaseDir, "in-cluster_query_alert_rule.yaml")
				)
				exutil.By("Create alert rule with expression about data provided by in-cluster prometheus")
				createResourceFromYaml(oc, ns, exampleAppRule)

				exutil.By("Get token of SA prometheus-k8s")
				token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

				exutil.By("Check labelmy is in the alert")
				checkMetric(oc, "https://alertmanager-main.openshift-monitoring.svc:9094/api/v2/alerts", token, "labelmy", 2*uwmLoadTime)
			})

			// author: tagao@redhat.com
			g.It("Author:tagao-Medium-42825-Expose EnforcedTargetLimit in the CMO configuration for UWM", func() {
				exutil.By("check user metrics")
				token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
				checkMetric(oc, "https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=version{namespace=\""+ns+"\"}'", token, "prometheus-example-app", 2*uwmLoadTime)

				exutil.By("scale deployment replicas to 2")
				oc.WithoutNamespace().Run("scale").Args("deployment", "prometheus-example-app", "--replicas=2", "-n", ns).Execute()

				exutil.By("check user metrics again, the user metrics can't be found from thanos-querier")
				checkMetric(oc, "https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=version{namespace=\""+ns+"\"}'", token, "\"result\":[]", 2*uwmLoadTime)
			})

			// author: tagao@redhat.com
			g.It("Author:tagao-Medium-49189-Enforce label scrape limits for UWM [Serial]", func() {
				var (
					invalidUWM = filepath.Join(monitoringBaseDir, "invalid-uwm.yaml")
				)
				exutil.By("delete uwm-config/cm-config at the end of a serial case")
				defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
				defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

				exutil.By("Get token of SA prometheus-k8s")
				token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

				exutil.By("query metrics from thanos-querier")
				checkMetric(oc, "https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=version'", token, "prometheus-example-app", uwmLoadTime)

				exutil.By("trigger label_limit exceed")
				createResourceFromYaml(oc, "openshift-user-workload-monitoring", invalidUWM)

				exutil.By("check in thanos-querier /targets api, it should complains the label_limit exceeded")
				checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/targets`, token, `label_limit exceeded`, 2*uwmLoadTime)

				exutil.By("trigger label_name_length_limit exceed")
				err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("cm", "user-workload-monitoring-config", "-p", `{"data": {"config.yaml": "prometheus:\n enforcedLabelLimit: 8\n enforcedLabelNameLengthLimit: 1\n enforcedLabelValueLengthLimit: 1\n"}}`, "--type=merge", "-n", "openshift-user-workload-monitoring").Execute()
				o.Expect(err).NotTo(o.HaveOccurred())

				exutil.By("check in thanos-querier /targets api, it should complains the label_name_length_limit exceeded")
				checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/targets`, token, `label_name_length_limit exceeded`, 2*uwmLoadTime)

				exutil.By("trigger label_value_length_limit exceed")
				err2 := oc.AsAdmin().WithoutNamespace().Run("patch").Args("cm", "user-workload-monitoring-config", "-p", `{"data": {"config.yaml": "prometheus:\n enforcedLabelLimit: 8\n enforcedLabelNameLengthLimit: 8\n enforcedLabelValueLengthLimit: 1\n"}}`, "--type=merge", "-n", "openshift-user-workload-monitoring").Execute()
				o.Expect(err2).NotTo(o.HaveOccurred())

				exutil.By("check in thanos-querier /targets api, it should complains the label_value_length_limit exceeded")
				checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/targets`, token, `label_value_length_limit exceeded`, 2*uwmLoadTime)

				exutil.By("relax restrictions")
				err3 := oc.AsAdmin().WithoutNamespace().Run("patch").Args("cm", "user-workload-monitoring-config", "-p", `{"data": {"config.yaml": "prometheus:\n enforcedLabelLimit: 10\n enforcedLabelNameLengthLimit: 10\n enforcedLabelValueLengthLimit: 50\n"}}`, "--type=merge", "-n", "openshift-user-workload-monitoring").Execute()
				o.Expect(err3).NotTo(o.HaveOccurred())

				exutil.By("able to see the metrics")
				checkMetric(oc, "https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=version'", token, "prometheus-example-app", 2*uwmLoadTime)
			})

			// TODO: could be merged with other RBAC tests
			// author: tagao@redhat.com
			g.It("Author:tagao-Medium-44805-Expose tenancy-aware labels and values of api v1 label endpoints for Thanos query", func() {
				var (
					rolebinding = filepath.Join(monitoringBaseDir, "rolebinding.yaml")
				)
				exutil.By("skip case for external OIDC cluster")
				isExternalOIDCCluster, err := exutil.IsExternalOIDCCluster(oc)
				o.Expect(err).NotTo(o.HaveOccurred())
				if isExternalOIDCCluster {
					g.Skip("Skipping the test as we are running against an external OIDC cluster.")
				}

				exutil.By("add RoleBinding to specific user")
				createResourceFromYaml(oc, ns, rolebinding)
				//oc -n ns1 patch RoleBinding view -p '{"subjects":[{"apiGroup":"rbac.authorization.k8s.io","kind":"User","name":"${user}"}]}'
				err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("RoleBinding", "view", "-p", `{"subjects":[{"apiGroup":"rbac.authorization.k8s.io","kind":"User","name":"`+oc.Username()+`"}]}`, "--type=merge", "-n", ns).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())

				exutil.By("get user API token")
				token := oc.UserConfig().BearerToken

				exutil.By("check namespace labels") //There are many labels, only check the few ones
				checkMetric(oc, "\"https://thanos-querier.openshift-monitoring.svc:9092/api/v1/labels?namespace="+oc.Namespace()+"\"", token, `"__name__"`, 2*uwmLoadTime)
				checkMetric(oc, "\"https://thanos-querier.openshift-monitoring.svc:9092/api/v1/labels?namespace="+oc.Namespace()+"\"", token, `"version"`, 2*uwmLoadTime)
				checkMetric(oc, "\"https://thanos-querier.openshift-monitoring.svc:9092/api/v1/labels?namespace="+oc.Namespace()+"\"", token, `"cluster_ip"`, 2*uwmLoadTime)

				exutil.By("show label value")
				checkMetric(oc, "\"https://thanos-querier.openshift-monitoring.svc:9092/api/v1/label/version/values?namespace="+oc.Namespace()+"\"", token, `"v0.4.1"`, 2*uwmLoadTime)

				exutil.By("check with a specific series")
				checkMetric(oc, "\"https://thanos-querier.openshift-monitoring.svc:9092/api/v1/series?match[]=version&namespace="+oc.Namespace()+"\"", token, `"service":"prometheus-example-app"`, 2*uwmLoadTime)
			})

			//author: tagao@redhat.com
			g.It("Author:tagao-High-73151-Update Prometheus user-workload to enable additional scrape metrics [Serial]", func() {
				var (
					exampleApp2                     = filepath.Join(monitoringBaseDir, "example-app-2-sampleLimit.yaml")
					approachingEnforcedSamplesLimit = filepath.Join(monitoringBaseDir, "approachingEnforcedSamplesLimit.yaml")
				)
				exutil.By("restore monitoring config")
				defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
				defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)
				defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("PrometheusRule", "monitoring-stack-alerts", "-n", ns).Execute()

				exutil.By("create example-app2")
				//example-app2 has sampleLimit and should be created under same ns with example-app
				createResourceFromYaml(oc, ns, exampleApp2)

				exutil.By("wait for pod ready")
				exutil.AssertPodToBeReady(oc, "prometheus-user-workload-0", "openshift-user-workload-monitoring")

				exutil.By("check extra-scrape-metrics added to uwm prometheus")
				output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheus", "user-workload", "-ojsonpath={.spec.enableFeatures}", "-n", "openshift-user-workload-monitoring").Output()
				o.Expect(output).To(o.ContainSubstring("extra-scrape-metrics"))
				o.Expect(err).NotTo(o.HaveOccurred())

				exutil.By("set up the alert rules")
				createResourceFromYaml(oc, ns, approachingEnforcedSamplesLimit)

				exutil.By("Get token of SA prometheus-k8s")
				token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

				exutil.By("check metrics")
				exampleAppPods, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", ns).Output()
				e2e.Logf("pods condition under ns:\n%s", exampleAppPods)
				checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=(scrape_sample_limit == 1)'`, token, "prometheus-example-app-2", uwmLoadTime)
				checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="ApproachingEnforcedSamplesLimit"}'`, token, `"prometheus-example-app-2"`, uwmLoadTime)
			})
		})

		// This test is already covered in test/e2e/config_test.go::TestUserWorkloadMonitorPrometheusK8Config
		// author: hongyli@redhat.com
		/* 		g.It("Author:hongyli-High-49745-High-50519-Retention for UWM Prometheus and thanos ruler", func() {
			exutil.By("Check retention size of prometheus user workload")
			checkRetention(oc, "openshift-user-workload-monitoring", "prometheus-user-workload", "storage.tsdb.retention.size=5GiB", uwmLoadTime)
			exutil.By("Check retention of prometheus user workload")
			checkRetention(oc, "openshift-user-workload-monitoring", "prometheus-user-workload", "storage.tsdb.retention.time=15d", 20)
			exutil.By("Check retention of thanos ruler")
			checkRetention(oc, "openshift-user-workload-monitoring", "thanos-ruler-user-workload", "retention=15d", uwmLoadTime)
		}) */

		// author: juzhao@redhat.com
		g.It("Author:juzhao-LEVEL0-Medium-42956-Should not have PrometheusNotIngestingSamples alert if enabled user workload monitoring only", func() {
			exutil.By("Get token of SA prometheus-k8s")
			token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

			exutil.By("check alerts, Should not have PrometheusNotIngestingSamples alert fired")
			checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="PrometheusNotIngestingSamples"}'`, token, `"result":[]`, uwmLoadTime)
		})

		// This test is already covered in test/e2e/config_test.go::TestUserWorkloadMonitorPrometheusK8Config
		// author: juzhao@redhat.com
		/* 		g.It("Author:juzhao-Medium-70998-PrometheusRestrictedConfig supports enabling sendExemplars", func() {
			exutil.By("check exemplar-storage is enabled")
			cmd := "-ojsonpath={.spec.enableFeatures[*]}"
			checkYamlconfig(oc, "openshift-user-workload-monitoring", "prometheus", "user-workload", cmd, "exemplar-storage", true)

			//check settings in UWM prometheus pods
			podNames, err := exutil.GetAllPodsWithLabel(oc, "openshift-user-workload-monitoring", "app.kubernetes.io/name=prometheus")
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range podNames {
				cmd = "-ojsonpath={.spec.containers[?(@.name==\"prometheus\")].args}"
				checkYamlconfig(oc, "openshift-user-workload-monitoring", "pod", pod, cmd, `--enable-feature=`, true)
				checkYamlconfig(oc, "openshift-user-workload-monitoring", "pod", pod, cmd, `exemplar-storage`, true)
			}
			exutil.By("check sendExemplars is true in UWM prometheus CRD")
			cmd = "-ojsonpath={.spec.remoteWrite}"
			checkYamlconfig(oc, "openshift-user-workload-monitoring", "prometheus", "user-workload", cmd, `"sendExemplars":true`, true)
		}) */

		// This test is already covered in test/e2e/config_test.go::TestUserWorkloadMonitorPrometheusK8Config and test/e2e/config_test.go::TestClusterMonitorPrometheusK8Config
		// author: tagao@redhat.com
		/* 		g.It("Author:tagao-LEVEL0-Medium-46301-Allow OpenShift users to configure query log file for Prometheus", func() {
			exutil.By("confirm prometheus-k8s-0 pod is ready for check")
			MONpod, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", "openshift-monitoring").Output()
			e2e.Logf("the MON pods condition: %s", MONpod)
			assertPodToBeReady(oc, "prometheus-k8s-0", "openshift-monitoring")
			ensurePodRemainsReady(oc, "prometheus-k8s-0", "openshift-monitoring", 30*time.Second, 5*time.Second)
			cmd := "ls /tmp/promethues_query.log"
			checkConfigInsidePod(oc, "openshift-monitoring", "prometheus", "prometheus-k8s-0", cmd, "promethues_query.log", true)

			exutil.By("check query log file for prometheus in openshift-monitoring")
			queryErr := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-monitoring", "-c", "prometheus", "prometheus-k8s-0", "--", "curl", "http://localhost:9090/api/v1/query?query=prometheus_build_info").Execute()
			o.Expect(queryErr).NotTo(o.HaveOccurred())
			cmd = "cat /tmp/promethues_query.log | grep prometheus_build_info"
			checkConfigInsidePod(oc, "openshift-monitoring", "prometheus", "prometheus-k8s-0", cmd, "prometheus_build_info", true)

			exutil.By("confirm prometheus-user-workload-0 pod is ready for check")
			UWMpod, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", "openshift-user-workload-monitoring").Output()
			e2e.Logf("the UWM pods condition: %s", UWMpod)
			assertPodToBeReady(oc, "prometheus-user-workload-0", "openshift-user-workload-monitoring")
			ensurePodRemainsReady(oc, "prometheus-user-workload-0", "openshift-user-workload-monitoring", 60*time.Second, 5*time.Second)
			cmd = "ls /tmp/uwm_query.log"
			checkConfigInsidePod(oc, "openshift-user-workload-monitoring", "prometheus", "prometheus-user-workload-0", cmd, "uwm_query.log", true)

			exutil.By("check query log file for prometheus in openshift-user-workload-monitoring")
			queryErr = oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-user-workload-monitoring", "-c", "prometheus", "prometheus-user-workload-0", "--", "curl", "http://localhost:9090/api/v1/query?query=up").Execute()
			o.Expect(queryErr).NotTo(o.HaveOccurred())
			cmd = "cat /tmp/uwm_query.log | grep up"
			checkConfigInsidePod(oc, "openshift-user-workload-monitoring", "prometheus", "prometheus-user-workload-0", cmd, "up", true)
		}) */

		// This test is already covered in pkg/manifests/manifests_test.go::TestRemoteWriteAuthorizationConfig
		// author: tagao@redhat.com
		/* 		g.It("Author:tagao-Medium-50008-Expose sigv4 settings for remote write in the CMO configuration [Serial]", func() {
			var (
				sigv4ClusterCM = filepath.Join(monitoringBaseDir, "sigv4-cluster-monitoring-cm.yaml")
				sigv4UwmCM     = filepath.Join(monitoringBaseDir, "sigv4-uwm-monitoring-cm.yaml")
				sigv4Secret    = filepath.Join(monitoringBaseDir, "sigv4-secret.yaml")
				sigv4SecretUWM = filepath.Join(monitoringBaseDir, "sigv4-secret-uwm.yaml")
			)
			exutil.By("delete secret/cm at the end of case")
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("secret", "sigv4-credentials-uwm", "-n", "openshift-user-workload-monitoring").Execute()
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("secret", "sigv4-credentials", "-n", "openshift-monitoring").Execute()
			defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
			defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

			exutil.By("Create sigv4 secret under openshift-monitoring")
			createResourceFromYaml(oc, "openshift-monitoring", sigv4Secret)

			exutil.By("Configure remote write sigv4 and enable user workload monitoring")
			createResourceFromYaml(oc, "openshift-monitoring", sigv4ClusterCM)

			exutil.By("confirm prometheus-k8s-0 pod is ready for check")
			pod, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", "openshift-monitoring", "-l", "app.kubernetes.io/name=prometheus").Output()
			e2e.Logf("the prometheus pods condition: %s", pod)
			exutil.AssertPodToBeReady(oc, "prometheus-k8s-0", "openshift-monitoring")

			exutil.By("Check sig4 config under openshift-monitoring")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "url: https://authorization.remotewrite.com/api/write")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "sigv4:")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "region: us-central1")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "access_key: basic_user")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "secret_key: basic_pass")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "profile: SomeProfile")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "role_arn: SomeRoleArn")

			exutil.By("Create sigv4 secret under openshift-user-workload-monitoring")
			createResourceFromYaml(oc, "openshift-user-workload-monitoring", sigv4SecretUWM)

			exutil.By("Configure remote write sigv4 setting for user workload monitoring")
			createResourceFromYaml(oc, "openshift-user-workload-monitoring", sigv4UwmCM)

			exutil.By("confirm prometheus-user-workload-0 pod is ready for check")
			pod, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", "openshift-user-workload-monitoring", "-l", "app.kubernetes.io/name=prometheus").Output()
			e2e.Logf("the prometheus pods condition: %s", pod)
			exutil.AssertPodToBeReady(oc, "prometheus-user-workload-0", "openshift-user-workload-monitoring")

			exutil.By("Check sig4 config under openshift-user-workload-monitoring")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "url: https://authorization.remotewrite.com/api/write")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "sigv4:")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "region: us-east2")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "access_key: basic_user_uwm")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "secret_key: basic_pass_uwm")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "profile: umw_Profile")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "role_arn: umw_RoleArn")
		}) */

		// This test is already covered in pkg/manifests/manifests_test.go::TestPrometheusK8sRemoteWriteOauth2
		// author: tagao@redhat.com
		/* 		g.It("Author:tagao-Medium-49694-Expose OAuth2 settings for remote write in the CMO configuration [Serial]", func() {
			var (
				oauth2ClusterCM = filepath.Join(monitoringBaseDir, "oauth2-cluster-monitoring-cm.yaml")
				oauth2UwmCM     = filepath.Join(monitoringBaseDir, "oauth2-uwm-monitoring-cm.yaml")
				oauth2Secret    = filepath.Join(monitoringBaseDir, "oauth2-secret.yaml")
				oauth2SecretUWM = filepath.Join(monitoringBaseDir, "oauth2-secret-uwm.yaml")
			)
			exutil.By("delete secret/cm at the end of case")
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("secret", "oauth2-credentials", "-n", "openshift-user-workload-monitoring").Execute()
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("secret", "oauth2-credentials", "-n", "openshift-monitoring").Execute()
			defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
			defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

			exutil.By("Create oauth2 secret under openshift-monitoring")
			createResourceFromYaml(oc, "openshift-monitoring", oauth2Secret)

			exutil.By("Configure remote write oauth2 and enable user workload monitoring")
			createResourceFromYaml(oc, "openshift-monitoring", oauth2ClusterCM)

			exutil.By("Check oauth2 config under openshift-monitoring")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "url: https://test.remotewrite.com/api/write")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "remote_timeout: 30s")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "client_id: basic_user")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "client_secret: basic_pass")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "token_url: https://example.com/oauth2/token")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "scope1")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "scope2")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "param1: value1")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "param2: value2")

			exutil.By("Create oauth2 secret under openshift-user-workload-monitoring")
			createResourceFromYaml(oc, "openshift-user-workload-monitoring", oauth2SecretUWM)

			exutil.By("Configure remote write oauth2 setting for user workload monitoring")
			createResourceFromYaml(oc, "openshift-user-workload-monitoring", oauth2UwmCM)

			exutil.By("Check oauth2 config under openshift-user-workload-monitoring")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "url: https://test.remotewrite.com/api/write")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "remote_timeout: 30s")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "client_id: basic_user")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "client_secret: basic_pass")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "token_url: https://example.com/oauth2/token")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "scope3")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "scope4")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "param3: value3")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "param4: value4")
		}) */

		// This test is already covered in pkg/manifests/manifests_test.go::TestAlertmanagerConfigPipeline
		//author: tagao@redhat.com
		/* 		g.It("Author:tagao-Medium-47519-Platform prometheus operator should reconcile AlertmanagerConfig resources from user namespaces [Serial]", func() {
			var (
				enableAltmgrConfig = filepath.Join(monitoringBaseDir, "enableUserAlertmanagerConfig.yaml")
				wechatConfig       = filepath.Join(monitoringBaseDir, "exampleAlertConfigAndSecret.yaml")
			)
			exutil.By("delete uwm-config/cm-config at the end of a serial case")
			defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
			defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

			exutil.By("enable alert manager config")
			createResourceFromYaml(oc, "openshift-monitoring", enableAltmgrConfig)
			exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")

			exutil.By("check the initial alertmanager configuration")
			checkAlertmanagerConfig(oc, "openshift-monitoring", "alertmanager-main-0", "alertname = Watchdog", true)

			exutil.By("create&check alertmanagerconfig under openshift-monitoring")
			createResourceFromYaml(oc, "openshift-monitoring", wechatConfig)
			output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("alertmanagerconfig/config-example", "secret/wechat-config", "-n", "openshift-monitoring").Output()
			o.Expect(output).To(o.ContainSubstring("config-example"))
			o.Expect(output).To(o.ContainSubstring("wechat-config"))

			exutil.By("check if the new created AlertmanagerConfig is reconciled in the Alertmanager configuration (should not)")
			checkAlertmanagerConfig(oc, "openshift-monitoring", "alertmanager-main-0", "wechat", false)

			exutil.By("delete the alertmanagerconfig/secret created under openshift-monitoring")
			oc.AsAdmin().WithoutNamespace().Run("delete").Args("alertmanagerconfig/config-example", "secret/wechat-config", "-n", "openshift-monitoring").Execute()

			exutil.By("create one new project, label the namespace and create the same AlertmanagerConfig")
			oc.SetupProject()
			ns := oc.Namespace()
			oc.AsAdmin().WithoutNamespace().Run("label").Args("namespace", ns, "openshift.io/user-monitoring=false").Execute()

			exutil.By("create&check alertmanagerconfig under the namespace")
			createResourceFromYaml(oc, ns, wechatConfig)
			output2, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("alertmanagerconfig/config-example", "secret/wechat-config", "-n", ns).Output()
			o.Expect(output2).To(o.ContainSubstring("config-example"))
			o.Expect(output2).To(o.ContainSubstring("wechat-config"))

			exutil.By("check if the new created AlertmanagerConfig is reconciled in the Alertmanager configuration (should not)")
			checkAlertmanagerConfig(oc, "openshift-monitoring", "alertmanager-main-0", "wechat", false)

			exutil.By("update the label to true")
			oc.AsAdmin().WithoutNamespace().Run("label").Args("namespace", ns, "openshift.io/user-monitoring=true", "--overwrite").Execute()

			exutil.By("check if the new created AlertmanagerConfig is reconciled in the Alertmanager configuration")
			checkAlertmanagerConfig(oc, "openshift-monitoring", "alertmanager-main-0", "wechat", true)

			exutil.By("set enableUserAlertmanagerConfig to false")
			err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("cm", "cluster-monitoring-config", "-p", `{"data": {"config.yaml": "alertmanagerMain:\n enableUserAlertmanagerConfig: false\n"}}`, "--type=merge", "-n", "openshift-monitoring").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("the AlertmanagerConfig from user project is removed")
			checkAlertmanagerConfig(oc, "openshift-monitoring", "alertmanager-main-0", "wechat", false)
		}) */

		// This test is already covered in pkg/manifests/manifests_test.go::TestPrometheusK8sRemoteWriteAuthorizationConfig and test/e2e/prometheus_test.go::TestPrometheusRemoteWrite
		/* 		g.It("Author:tagao-Medium-49404-Medium-49176-Expose Authorization settings for remote write in the CMO configuration, Add the relabel config to all user-supplied remote_write configurations [Serial]", func() {
			var (
				authClusterCM = filepath.Join(monitoringBaseDir, "auth-cluster-monitoring-cm.yaml")
				authUwmCM     = filepath.Join(monitoringBaseDir, "auth-uwm-monitoring-cm.yaml")
				authSecret    = filepath.Join(monitoringBaseDir, "auth-secret.yaml")
				authSecretUWM = filepath.Join(monitoringBaseDir, "auth-secret-uwm.yaml")
			)
			exutil.By("delete secret/cm at the end of case")
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("secret", "rw-auth", "-n", "openshift-user-workload-monitoring").Execute()
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("secret", "rw-auth", "-n", "openshift-monitoring").Execute()
			defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
			defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

			exutil.By("Create auth secret under openshift-monitoring")
			createResourceFromYaml(oc, "openshift-monitoring", authSecret)

			exutil.By("Configure remote write auth and enable user workload monitoring")
			createResourceFromYaml(oc, "openshift-monitoring", authClusterCM)

			exutil.By("confirm prometheus-k8s-0 pod is ready for check")
			pod, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", "openshift-monitoring", "-l", "app.kubernetes.io/name=prometheus").Output()
			e2e.Logf("the prometheus pods condition: %s", pod)
			exutil.AssertPodToBeReady(oc, "prometheus-k8s-0", "openshift-monitoring")

			exutil.By("Check auth config under openshift-monitoring")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "url: https://remote-write.endpoint")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "target_label: __tmp_openshift_cluster_id__")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "url: https://basicAuth.remotewrite.com/api/write")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "username: basic_user")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "password: basic_pass")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "url: https://authorization.remotewrite.com/api/write")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "__tmp_openshift_cluster_id__")
			checkRmtWrtConfig(oc, "openshift-monitoring", "prometheus-k8s-0", "target_label: cluster_id")

			exutil.By("Create auth secret under openshift-user-workload-monitoring")
			createResourceFromYaml(oc, "openshift-user-workload-monitoring", authSecretUWM)

			exutil.By("Configure remote write auth setting for user workload monitoring")
			createResourceFromYaml(oc, "openshift-user-workload-monitoring", authUwmCM)

			exutil.By("confirm prometheus-user-workload-0 pod is ready for check")
			pod, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", "openshift-user-workload-monitoring", "-l", "app.kubernetes.io/name=prometheus").Output()
			e2e.Logf("the prometheus pods condition: %s", pod)
			exutil.AssertPodToBeReady(oc, "prometheus-user-workload-0", "openshift-user-workload-monitoring")

			exutil.By("Check auth config under openshift-user-workload-monitoring")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "url: https://remote-write.endpoint")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "target_label: __tmp_openshift_cluster_id__")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "url: https://basicAuth.remotewrite.com/api/write")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "username: basic_user")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "password: basic_pass")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "url: https://bearerTokenFile.remotewrite.com/api/write")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "url: https://authorization.remotewrite.com/api/write")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "__tmp_openshift_cluster_id__")
			checkRmtWrtConfig(oc, "openshift-user-workload-monitoring", "prometheus-user-workload-0", "target_label: cluster_id_1")
		}) */

		// author: tagao@redhat.com
		g.It("Author:tagao-Low-43037-Should not have error for oc adm inspect clusteroperator monitoring command", func() {
			exutil.By("delete must-gather file at the end of case")
			defer exec.Command("bash", "-c", "rm -rf /tmp/must-gather-43037").Output()

			exutil.By("oc adm inspect clusteroperator monitoring")
			exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
			output, _ := oc.AsAdmin().WithoutNamespace().Run("adm").Args("inspect", "clusteroperator", "monitoring", "--dest-dir=/tmp/must-gather-43037").Output()
			o.Expect(output).NotTo(o.ContainSubstring("error"))
		})

		// author: tagao@redhat.com
		g.It("Author:tagao-Medium-32224-Separate user workload configuration [Serial]", func() {
			var (
				separateUwmConf = filepath.Join(monitoringBaseDir, "separate-uwm-config.yaml")
			)
			exutil.By("delete uwm-config/cm-config and bound pvc at the end of a serial case")
			defer func() {
				PvcNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pvc", "-ojsonpath={.items[*].metadata.name}", "-l", "app.kubernetes.io/instance=user-workload", "-n", "openshift-user-workload-monitoring").Output()
				o.Expect(err).NotTo(o.HaveOccurred())
				for _, pvc := range strings.Fields(PvcNames) {
					oc.AsAdmin().WithoutNamespace().Run("delete").Args("pvc", pvc, "-n", "openshift-user-workload-monitoring").Execute()
				}
			}()
			defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
			defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

			exutil.By("this case should execute on cluster which have storage class")
			checkSc, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("sc").Output()
			if checkSc == "{}" || !strings.Contains(checkSc, "default") {
				g.Skip("This case should execute on cluster which have default storage class!")
			}

			exutil.By("get master node names with label")
			NodeNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", "-l", "node-role.kubernetes.io/master", "-ojsonpath={.items[*].metadata.name}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			nodeNameList := strings.Fields(NodeNames)

			exutil.By("add labels to master nodes, and delete them at the end of case")
			for _, name := range nodeNameList {
				defer oc.AsAdmin().WithoutNamespace().Run("label").Args("node", name, "uwm-").Execute()
				err = oc.AsAdmin().WithoutNamespace().Run("label").Args("node", name, "uwm=deploy").Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
			}

			exutil.By("create the separate user workload configuration")
			createResourceFromYaml(oc, "openshift-user-workload-monitoring", separateUwmConf)

			exutil.By("check remoteWrite metrics")
			token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
			checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=prometheus_remote_storage_shards'`, token, `"url":"http://localhost:1234/receive"`, 3*uwmLoadTime)

			exutil.By("check prometheus-user-workload pods are bound to PVCs, check cpu and memory")
			PodNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-ojsonpath={.items[*].metadata.name}", "-l", "app.kubernetes.io/name=prometheus", "-n", "openshift-user-workload-monitoring").Output()
			PodNameList := strings.Fields(PodNames)
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range PodNameList {
				output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", pod, "-ojsonpath={.spec.volumes[]}", "-n", "openshift-user-workload-monitoring").Output()
				o.Expect(output).To(o.ContainSubstring("uwm-prometheus"))
				output, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", pod, `-ojsonpath={.spec.containers[?(@.name=="prometheus")].resources.requests}`, "-n", "openshift-user-workload-monitoring").Output()
				o.Expect(output).To(o.ContainSubstring(`"cpu":"200m","memory":"1Gi"`))
			}

			exutil.By("check thanos-ruler-user-workload pods are bound to PVCs, check cpu and memory")
			PodNames, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-ojsonpath={.items[*].metadata.name}", "-l", "app.kubernetes.io/name=thanos-ruler", "-n", "openshift-user-workload-monitoring").Output()
			PodNameList = strings.Fields(PodNames)
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range PodNameList {
				output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", pod, "-ojsonpath={.spec.volumes[]}", "-n", "openshift-user-workload-monitoring").Output()
				o.Expect(output).To(o.ContainSubstring("thanosruler"))
				output, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", pod, `-ojsonpath={.spec.containers[?(@.name=="thanos-ruler")].resources.requests}`, "-n", "openshift-user-workload-monitoring").Output()
				o.Expect(output).To(o.ContainSubstring(`"cpu":"20m","memory":"50Mi"`))
			}

			exutil.By("toleration settings check")
			PodNames, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-ojsonpath={.items[*].metadata.name}", "-n", "openshift-user-workload-monitoring").Output()
			PodNameList = strings.Fields(PodNames)
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range PodNameList {
				output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", pod, "-ojsonpath={.spec.tolerations}", "-n", "openshift-user-workload-monitoring").Output()
				o.Expect(output).To(o.ContainSubstring("node-role.kubernetes.io/master"))
				o.Expect(output).To(o.ContainSubstring(`"operator":"Exists"`))
			}
			exutil.By("prometheus.enforcedSampleLimit check")
			output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheus", "user-workload", "-ojsonpath={.spec.enforcedSampleLimit}", "-n", "openshift-user-workload-monitoring").Output()
			o.Expect(output).To(o.ContainSubstring("2"))

			exutil.By("prometheus.retention check")
			output, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheus", "user-workload", "-ojsonpath={.spec.retention}", "-n", "openshift-user-workload-monitoring").Output()
			o.Expect(output).To(o.ContainSubstring("48h"))
		})

		// author: tagao@redhat.com
		g.It("Author:tagao-LEVEL0-Medium-50954-Allow the deployment of a dedicated UWM Alertmanager [Serial]", func() {
			var (
				dedicatedUWMalertmanager = filepath.Join(monitoringBaseDir, "dedicated-uwm-alertmanager.yaml")
				exampleAlert             = filepath.Join(monitoringBaseDir, "example-alert-rule.yaml")
				AlertmanagerConfig       = filepath.Join(monitoringBaseDir, "exampleAlertConfigAndSecret.yaml")
			)
			exutil.By("delete uwm-config/cm-config and bound pvc at the end of a serial case")
			defer func() {
				PvcNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pvc", "-ojsonpath={.items[*].metadata.name}", "-l", "alertmanager=user-workload", "-n", "openshift-user-workload-monitoring").Output()
				o.Expect(err).NotTo(o.HaveOccurred())
				for _, pvc := range strings.Fields(PvcNames) {
					oc.AsAdmin().WithoutNamespace().Run("delete").Args("pvc", pvc, "-n", "openshift-user-workload-monitoring").Execute()
				}
			}()
			defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
			defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

			exutil.By("this case should execute on cluster which have storage class")
			checkSc, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("sc").Output()
			if checkSc == "{}" || !strings.Contains(checkSc, "default") {
				g.Skip("This case should execute on cluster which have default storage class!")
			}

			// hypershift-hosted cluster do not have master node
			exutil.By("get master node names with label")
			NodeNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", "-l", "node-role.kubernetes.io/master", "--ignore-not-found", "-ojsonpath={.items[*].metadata.name}").Output()
			if NodeNames == "" {
				g.Skip("This case should execute on cluster which have master node!")
			}
			o.Expect(err).NotTo(o.HaveOccurred())
			nodeNameList := strings.Fields(NodeNames)

			exutil.By("add labels to master nodes, and delete them at the end of case")
			for _, name := range nodeNameList {
				defer oc.AsAdmin().WithoutNamespace().Run("label").Args("node", name, "uwm-").Execute()
				err = oc.AsAdmin().WithoutNamespace().Run("label").Args("node", name, "uwm=alertmanager").Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
			}

			exutil.By("create the dedicated UWM Alertmanager configuration")
			createResourceFromYaml(oc, "openshift-user-workload-monitoring", dedicatedUWMalertmanager)

			exutil.By("deploy prometheusrule and alertmanagerconfig to user project")
			oc.SetupProject()
			ns := oc.Namespace()
			createResourceFromYaml(oc, ns, exampleAlert)
			createResourceFromYaml(oc, ns, AlertmanagerConfig)

			exutil.By("check all pods are created")
			exutil.AssertAllPodsToBeReady(oc, "openshift-user-workload-monitoring")

			exutil.By("confirm thanos-ruler is ready")
			exutil.AssertPodToBeReady(oc, "thanos-ruler-user-workload-0", "openshift-user-workload-monitoring")
			thanosPod, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-l", " app.kubernetes.io/name=thanos-ruler", "-n", "openshift-user-workload-monitoring").Output()
			e2e.Logf("thanos-ruler pods: \n%v", thanosPod)
			thanosSaErr := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 60*time.Second, true, func(context.Context) (bool, error) {
				thanosSa, err := oc.AsAdmin().Run("get").Args("sa", "thanos-ruler", "-n", "openshift-user-workload-monitoring").Output()
				if err != nil || strings.Contains(thanosSa, "not found") {
					return false, nil
				}
				return true, nil
			})
			exutil.AssertWaitPollNoErr(thanosSaErr, "sa not created")

			exutil.By("check the alerts could be found in alertmanager under openshift-user-workload-monitoring project")
			token := getSAToken(oc, "thanos-ruler", "openshift-user-workload-monitoring")
			checkMetric(oc, `https://alertmanager-user-workload.openshift-user-workload-monitoring.svc:9095/api/v2/alerts`, token, "TestAlert1", 3*uwmLoadTime)

			exutil.By("check the alerts could not be found in openshift-monitoring project")
			//same as: checkMetric(oc, `https://alertmanager-main.openshift-monitoring.svc:9094/api/v2/alerts?&filter={alertname="TestAlert1"}`, token, "[]", 3*uwmLoadTime)
			checkAlertNotExist(oc, "https://alertmanager-main.openshift-monitoring.svc:9094/api/v2/alerts", token, "TestAlert1", 3*uwmLoadTime)

			exutil.By("get alertmanager pod names")
			PodNames, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-ojsonpath={.items[*].metadata.name}", "-l", "app.kubernetes.io/name=alertmanager", "-n", "openshift-user-workload-monitoring").Output()
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("check alertmanager pod resources limits and requests")
			for _, pod := range strings.Fields(PodNames) {
				output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", pod, `-ojsonpath={.spec.containers[?(@.name=="alertmanager")].resources.limits}`, "-n", "openshift-user-workload-monitoring").Output()
				o.Expect(output).To(o.ContainSubstring(`"cpu":"100m","memory":"250Mi"`))
				o.Expect(err).NotTo(o.HaveOccurred())
				output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", pod, `-ojsonpath={.spec.containers[?(@.name=="alertmanager")].resources.requests}`, "-n", "openshift-user-workload-monitoring").Output()
				o.Expect(output).To(o.ContainSubstring(`"cpu":"40m","memory":"200Mi"`))
				o.Expect(err).NotTo(o.HaveOccurred())
			}

			exutil.By("check alertmanager pod are bound pvcs")
			for _, pod := range strings.Fields(PodNames) {
				output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", pod, "-ojsonpath={.spec.volumes[]}", "-n", "openshift-user-workload-monitoring").Output()
				o.Expect(output).To(o.ContainSubstring("uwm-alertmanager"))
				o.Expect(err).NotTo(o.HaveOccurred())
			}

			exutil.By("check AlertmanagerConfigs are take effect")
			for _, pod := range strings.Fields(PodNames) {
				checkAlertmanagerConfig(oc, "openshift-user-workload-monitoring", pod, "api_url: http://wechatserver:8080/", true)
			}

			exutil.By("check logLevel is correctly set")
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("alertmanager/user-workload", "-ojsonpath={.spec.logLevel}", "-n", "openshift-user-workload-monitoring").Output()
			o.Expect(output).To(o.ContainSubstring("debug"))
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("check logLevel is take effect")
			for _, pod := range strings.Fields(PodNames) {
				output, err = oc.AsAdmin().WithoutNamespace().Run("logs").Args("-c", "alertmanager", pod, "-n", "openshift-user-workload-monitoring").Output()
				o.Expect(err).NotTo(o.HaveOccurred())
				if !strings.Contains(strings.ToLower(output), "level=debug") {
					e2e.Failf("logLevel is wrong or not take effect")
				}
			}

			exutil.By("disable alertmanager in user-workload-monitoring-config")
			//oc patch cm user-workload-monitoring-config -p '{"data": {"config.yaml": "alertmanager:\n  enabled: false\n"}}' --type=merge -n openshift-user-workload-monitoring
			err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("cm", "user-workload-monitoring-config", "-p", `{"data": {"config.yaml": "alertmanager:\n  enabled: false\n"}}`, "--type=merge", "-n", "openshift-user-workload-monitoring").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("should found user project alerts in platform alertmanager")
			checkMetric(oc, `https://alertmanager-main.openshift-monitoring.svc:9094/api/v2/alerts`, token, "TestAlert1", 3*uwmLoadTime)

			exutil.By("UWM alertmanager pod should disappear") //need time to wait pod fully terminated, put this step after the checkMetric
			checkPodDeleted(oc, "openshift-user-workload-monitoring", "app.kubernetes.io/name=alertmanager", "alertmanager")
		})

		// This test is already covered by  test/e2e/thanos_ruler_test.go::TestUserWorkloadThanosRulerWithAdditionalAlertmanagers and test/e2e/user_workload_monitoring_test.go::TestUserWorkloadMonitoringWithAdditionalAlertmanagerConfigs
		// author: tagao@redhat.com
		/* 		g.It("ConnectedOnly-Author:tagao-Medium-43286-Allow sending alerts to external Alertmanager for user workload monitoring components - enabled in-cluster alertmanager", func() {
		   			var (
		   				testAlertmanager = filepath.Join(monitoringBaseDir, "example-alertmanager.yaml")
		   				exampleAlert     = filepath.Join(monitoringBaseDir, "example-alert-rule.yaml")
		   				exampleAlert2    = filepath.Join(monitoringBaseDir, "leaf-prometheus-rule.yaml")
		   			)
		   			exutil.By("create alertmanager and set external alertmanager for prometheus/thanosRuler under openshift-user-workload-monitoring")
		   			createResourceFromYaml(oc, "openshift-user-workload-monitoring", testAlertmanager)
		   			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("alertmanager", "test-alertmanager", "-n", "openshift-user-workload-monitoring").Execute()

		   			exutil.By("check alertmanager pod is created")
		   			alertmanagerTestPodCheck(oc)

		   			exutil.By("skip case on disconnected cluster")
		   			output, err := oc.AsAdmin().Run("get").Args("pod", "alertmanager-test-alertmanager-0", "-n", "openshift-user-workload-monitoring").Output()
		   			o.Expect(err).NotTo(o.HaveOccurred())
		   			e2e.Logf("the pod condition: %s", output)
		   			if output != "{}" && strings.Contains(output, "ImagePullBackOff") {
		   				g.Skip("This case can not execute on a disconnected cluster!")
		   			}

		   			exutil.By("create example PrometheusRule under user namespace")
		   			oc.SetupProject()
		   			ns1 := oc.Namespace()
		   			createResourceFromYaml(oc, ns1, exampleAlert)

		   			exutil.By("create another user namespace then create PrometheusRule with leaf-prometheus label")
		   			oc.SetupProject()
		   			ns2 := oc.Namespace()
		   			createResourceFromYaml(oc, ns2, exampleAlert2)

		   			exutil.By("Get token of SA prometheus-k8s")
		   			token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

		   			exutil.By("check the user alerts TestAlert1 and TestAlert2 are shown in \"in-cluster alertmanager\" API")
		   			checkMetric(oc, `https://alertmanager-main.openshift-monitoring.svc:9094/api/v2/alerts?filter={alertname="TestAlert1"}`, token, "TestAlert1", uwmLoadTime)
		   			checkMetric(oc, `https://alertmanager-main.openshift-monitoring.svc:9094/api/v2/alerts?filter={alertname="TestAlert1"}`, token, `"generatorURL":"https://console-openshift-console.`, uwmLoadTime)
		   			checkMetric(oc, `https://alertmanager-main.openshift-monitoring.svc:9094/api/v2/alerts?filter={alertname="TestAlert2"}`, token, "TestAlert2", uwmLoadTime)
		   			checkMetric(oc, `https://alertmanager-main.openshift-monitoring.svc:9094/api/v2/alerts?filter={alertname="TestAlert2"}`, token, `"generatorURL":"https://console-openshift-console.`, uwmLoadTime)

		   			exutil.By("check the alerts are also sent to external alertmanager")
		   			queryFromPod(oc, `http://alertmanager-operated.openshift-user-workload-monitoring.svc:9093/api/v2/alerts?filter={alertname="TestAlert1"}`, token, "openshift-user-workload-monitoring", "thanos-ruler-user-workload-0", "thanos-ruler", "TestAlert1", uwmLoadTime)
		   			queryFromPod(oc, `http://alertmanager-operated.openshift-user-workload-monitoring.svc:9093/api/v2/alerts?filter={alertname="TestAlert1"}`, token, "openshift-user-workload-monitoring", "thanos-ruler-user-workload-0", "thanos-ruler", `"generatorURL":"https://console-openshift-console.`, uwmLoadTime)
		   			queryFromPod(oc, `http://alertmanager-operated.openshift-user-workload-monitoring.svc:9093/api/v2/alerts?filter={alertname="TestAlert2"}`, token, "openshift-user-workload-monitoring", "thanos-ruler-user-workload-0", "thanos-ruler", "TestAlert2", uwmLoadTime)
		   			queryFromPod(oc, `http://alertmanager-operated.openshift-user-workload-monitoring.svc:9093/api/v2/alerts?filter={alertname="TestAlert2"}`, token, "openshift-user-workload-monitoring", "thanos-ruler-user-workload-0", "thanos-ruler", `"generatorURL":"https://console-openshift-console.`, uwmLoadTime)
		   		})
		*/
		// author: tagao@redhat.com
		g.It("Author:tagao-ConnectedOnly-Medium-43311-Allow sending alerts to external Alertmanager for user workload monitoring components - disabled in-cluster alertmanager [Serial]", func() {
			var (
				InClusterMonitoringCM = filepath.Join(monitoringBaseDir, "disLocalAlert-setExternalAlert-prometheus.yaml")
				testAlertmanager      = filepath.Join(monitoringBaseDir, "example-alertmanager.yaml")
				exampleAlert          = filepath.Join(monitoringBaseDir, "example-alert-rule.yaml")
			)
			exutil.By("Restore cluster monitoring stack default configuration")
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("alertmanager", "test-alertmanager", "-n", "openshift-user-workload-monitoring", "--ignore-not-found").Execute()
			defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
			defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

			exutil.By("disable local alertmanager and set external manager for prometheus")
			createResourceFromYaml(oc, "openshift-monitoring", InClusterMonitoringCM)

			exutil.By("create alertmanager and set external alertmanager for prometheus/thanosRuler under openshift-user-workload-monitoring")
			createResourceFromYaml(oc, "openshift-user-workload-monitoring", testAlertmanager)

			exutil.By("check alertmanager pod is created")
			alertmanagerTestPodCheck(oc)

			exutil.By("skip case on disconnected cluster")
			cmCheck, _ := oc.AsAdmin().Run("get").Args("cm", "cluster-monitoring-config", "-n", "openshift-monitoring", "-ojson").Output()
			poCheck, _ := oc.AsAdmin().Run("get").Args("pod", "-n", "openshift-monitoring").Output()
			if !strings.Contains(cmCheck, "telemeter") && !strings.Contains(poCheck, "telemeter") {
				g.Skip("This case can not execute on a disconnected cluster!")
			}

			exutil.By("create example PrometheusRule under user namespace")
			oc.SetupProject()
			ns1 := oc.Namespace()
			createResourceFromYaml(oc, ns1, exampleAlert)

			exutil.By("Get token of SA prometheus-k8s")
			token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

			exutil.By("check the user alerts TestAlert1 and in-cluster Watchdog alerts are shown in \"thanos-querier\" API")
			checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="TestAlert1"}'`, token, `TestAlert1`, 3*platformLoadTime)
			checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="Watchdog"}'`, token, `Watchdog`, 3*platformLoadTime)

			exutil.By("check the alerts are also sent to external alertmanager, include the in-cluster and user project alerts")
			queryFromPod(oc, `http://alertmanager-operated.openshift-user-workload-monitoring.svc:9093/api/v2/alerts?filter={alertname="TestAlert1"}`, token, "openshift-user-workload-monitoring", "thanos-ruler-user-workload-0", "thanos-ruler", "TestAlert1", 3*uwmLoadTime)
			queryFromPod(oc, `http://alertmanager-operated.openshift-user-workload-monitoring.svc:9093/api/v2/alerts?filter={alertname="Watchdog"}`, token, "openshift-user-workload-monitoring", "thanos-ruler-user-workload-0", "thanos-ruler", "Watchdog", 3*uwmLoadTime)
		})

		// author: tagao@redhat.com
		g.It("Author:tagao-ConnectedOnly-Medium-44815-Configure containers to honor the global tlsSecurityProfile", func() {
			exutil.By("get global tlsSecurityProfile")
			// % oc get kubeapiservers.operator.openshift.io cluster -o jsonpath='{.spec.observedConfig.servingInfo.cipherSuites}'
			cipherSuites, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("kubeapiservers.operator.openshift.io", "cluster", "-ojsonpath={.spec.observedConfig.servingInfo.cipherSuites}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			cipherSuitesFormat := strings.ReplaceAll(cipherSuites, "\"", "")
			cipherSuitesFormat = strings.ReplaceAll(cipherSuitesFormat, "[", "")
			cipherSuitesFormat = strings.ReplaceAll(cipherSuitesFormat, "]", "")
			e2e.Logf("cipherSuites: %s", cipherSuitesFormat)
			// % oc get kubeapiservers.operator.openshift.io cluster -o jsonpath='{.spec.observedConfig.servingInfo.minTLSVersion}'
			minTLSVersion, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("kubeapiservers.operator.openshift.io", "cluster", "-ojsonpath={.spec.observedConfig.servingInfo.minTLSVersion}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("check tls-cipher-suites and tls-min-version for metrics-server under openshift-monitoring")
			// % oc -n openshift-monitoring get deploy metrics-server -ojsonpath='{.spec.template.spec.containers[?(@tls-cipher-suites=)].args}'
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("deploy", "metrics-server", "-ojsonpath={.spec.template.spec.containers[?(@tls-cipher-suites=)].args}", "-n", "openshift-monitoring").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			if !strings.Contains(output, cipherSuitesFormat) {
				e2e.Failf("tls-cipher-suites is different from global setting! %s", output)
			}
			if !strings.Contains(output, minTLSVersion) {
				e2e.Failf("tls-min-version is different from global setting! %s", output)
			}

			exutil.By("check tls-cipher-suites and tls-min-version for all pods which use kube-rbac-proxy container under openshift-monitoring/openshift-user-workload-monitoring")
			//oc get pod -l app.kubernetes.io/name=alertmanager -n openshift-monitoring
			alertmanagerPodNames, err := exutil.GetAllPodsWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/name=alertmanager")
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range alertmanagerPodNames {
				cmd := "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy\")].args}"
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, minTLSVersion, true)
				cmd = "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy-metric\")].args}"
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, minTLSVersion, true)
			}
			//oc get pod -l app.kubernetes.io/name=node-exporter -n openshift-monitoring
			nePodNames, err := exutil.GetAllPodsWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/name=node-exporter")
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range nePodNames {
				cmd := "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy\")].args}"
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, minTLSVersion, true)
			}
			//oc get pod -l app.kubernetes.io/name=kube-state-metrics -n openshift-monitoring
			ksmPodNames, err := exutil.GetAllPodsWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/name=kube-state-metrics")
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range ksmPodNames {
				cmd := "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy-main\")].args}"
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, minTLSVersion, true)
				cmd = "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy-self\")].args}"
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, minTLSVersion, true)
			}
			//oc get pod -l app.kubernetes.io/name=openshift-state-metrics -n openshift-monitoring
			osmPodNames, err := exutil.GetAllPodsWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/name=openshift-state-metrics")
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range osmPodNames {
				cmd := "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy-main\")].args}"
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, minTLSVersion, true)
				cmd = "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy-self\")].args}"
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, minTLSVersion, true)
			}
			//oc get pod -l app.kubernetes.io/name=prometheus -n openshift-monitoring
			pk8sPodNames, err := exutil.GetAllPodsWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/name=prometheus")
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range pk8sPodNames {
				cmd := "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy\")].args}"
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, minTLSVersion, true)
				cmd = "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy-thanos\")].args}"
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, minTLSVersion, true)
			}
			//oc get pod -l app.kubernetes.io/name=prometheus-operator -n openshift-monitoring
			poPodNames, err := exutil.GetAllPodsWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/name=prometheus-operator")
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range poPodNames {
				cmd := "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy\")].args}"
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, minTLSVersion, true)
			}
			//oc get pod -l app.kubernetes.io/name=telemeter-client -n openshift-monitoring
			tcPodNames, err := exutil.GetAllPodsWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/name=telemeter-client")
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range tcPodNames {
				cmd := "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy\")].args}"
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, minTLSVersion, true)
			}
			//oc get pod -l app.kubernetes.io/name=thanos-query -n openshift-monitoring
			tqPodNames, err := exutil.GetAllPodsWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/name=thanos-query")
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range tqPodNames {
				cmd := "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy\")].args}"
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, minTLSVersion, true)
				cmd = "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy-rules\")].args}"
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, minTLSVersion, true)
				cmd = "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy-metrics\")].args}"
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, minTLSVersion, true)
			}
			//oc get pod -l app.kubernetes.io/name=prometheus-operator -n openshift-user-workload-monitoring
			UWMpoPodNames, err := exutil.GetAllPodsWithLabel(oc, "openshift-user-workload-monitoring", "app.kubernetes.io/name=prometheus-operator")
			// `UWMpoPodNames` should only have one value, otherwise means there are PO pods in progress deleting
			e2e.Logf("UWMpoPodNames: %v", UWMpoPodNames)
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range UWMpoPodNames {
				cmd := "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy\")].args}"
				checkYamlconfig(oc, "openshift-user-workload-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-user-workload-monitoring", "pod", pod, cmd, minTLSVersion, true)
			}
			//oc get pod -l app.kubernetes.io/instance=user-workload -n openshift-user-workload-monitoring
			UWMPodNames, err := exutil.GetAllPodsWithLabel(oc, "openshift-user-workload-monitoring", "app.kubernetes.io/instance=user-workload")
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range UWMPodNames {
				// Multiple container: kube-rbac-**** under this label, use fuzzy query
				cmd := "-ojsonpath={.spec.containers[?(@tls-cipher-suites)].args}"
				checkYamlconfig(oc, "openshift-user-workload-monitoring", "pod", pod, cmd, cipherSuitesFormat, true)
				checkYamlconfig(oc, "openshift-user-workload-monitoring", "pod", pod, cmd, minTLSVersion, true)
			}
		})

		// The test is already covered in pkg/manifests/manifests_test.go::TestPrometheusUserWorkloadConfiguration
		// author: tagao@redhat.com
		/* 		g.It("Author:tagao-LEVEL0-Medium-68237-Add the trusted CA bundle in the Prometheus user workload monitoring pods", func() {
			exutil.By("confirm UWM pod is ready")
			exutil.AssertPodToBeReady(oc, "prometheus-user-workload-0", "openshift-user-workload-monitoring")

			exutil.By("check configmap under namespace: openshift-user-workload-monitoring")
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("cm", "-n", "openshift-user-workload-monitoring").Output()
			o.Expect(output).To(o.ContainSubstring("prometheus-user-workload-trusted-ca-bundle"))
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("check the trusted CA bundle is applied to the pod")
			PodNames, err := exutil.GetAllPodsWithLabel(oc, "openshift-user-workload-monitoring", "app.kubernetes.io/name=prometheus")
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range PodNames {
				cmd := "-ojsonpath={.spec.containers[?(@.name==\"prometheus\")].volumeMounts}"
				checkYamlconfig(oc, "openshift-user-workload-monitoring", "pod", pod, cmd, "prometheus-user-workload-trusted-ca-bundle", true)
				cmd = "-ojsonpath={.spec.volumes[?(@.name==\"prometheus-user-workload-trusted-ca-bundle\")]}"
				checkYamlconfig(oc, "openshift-user-workload-monitoring", "pod", pod, cmd, "prometheus-user-workload-trusted-ca-bundle", true)
			}
		}) */

		// The test is already covered in pkg/operator/operator_test.go::TestGenerateRunReportFromTaskErrors
		//author: tagao@redhat.com
		/* 		g.It("Author:tagao-Medium-69084-user workLoad components failures leading to CMO degradation/unavailability should be easy to identify [Slow] [Disruptive]", func() {
			var (
				UserWorkloadTasksFailed = filepath.Join(monitoringBaseDir, "UserWorkloadTasksFailed.yaml")
			)
			exutil.By("delete uwm-config/cm-config at the end of a serial case")
			defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
			defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

			exutil.By("trigger UserWorkloadTasksFailed")
			createResourceFromYaml(oc, "openshift-user-workload-monitoring", UserWorkloadTasksFailed)

			exutil.By("check logs in CMO should see UserWorkloadTasksFailed")
			CMOPodName, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", "openshift-monitoring", "-l", "app.kubernetes.io/name=cluster-monitoring-operator", "-ojsonpath={.items[].metadata.name}").Output()
			exutil.WaitAndGetSpecificPodLogs(oc, "openshift-monitoring", "cluster-monitoring-operator", CMOPodName, "UserWorkloadTasksFailed")
		}) */

		// TODO: could be merged with other RBAC tests
		//author: tagao@redhat.com
		g.It("Author:tagao-Medium-73112-replace OAuth proxy for Thanos Ruler", func() {
			exutil.By("check new secret thanos-user-workload-kube-rbac-proxy-web added")
			exutil.AssertPodToBeReady(oc, "prometheus-user-workload-0", "openshift-user-workload-monitoring")
			checkSecret, err := oc.AsAdmin().Run("get").Args("secret", "thanos-user-workload-kube-rbac-proxy-web", "-n", "openshift-user-workload-monitoring").Output()
			o.Expect(checkSecret).NotTo(o.ContainSubstring("not found"))
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("check old secret thanos-ruler-oauth-cookie removed")
			checkSecret, _ = oc.AsAdmin().Run("get").Args("secret", "thanos-ruler-oauth-cookie", "-n", "openshift-user-workload-monitoring").Output()
			o.Expect(checkSecret).To(o.ContainSubstring("not found"))

			exutil.By("check thanos-ruler sa, `annotations` should be removed")
			checkSa, err := oc.AsAdmin().Run("get").Args("sa", "thanos-ruler", "-n", "openshift-user-workload-monitoring", "-ojsonpath={.metadata.annotations}").Output()
			o.Expect(checkSa).NotTo(o.ContainSubstring("Route"))
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("check thanos-ruler-user-workload pods, thanos-ruler-proxy container is removed")
			checkPO, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "thanos-ruler-user-workload-0", "-ojsonpath={.spec.containers[*].name}", "-n", "openshift-user-workload-monitoring").Output()
			o.Expect(checkPO).NotTo(o.ContainSubstring("thanos-ruler-proxy"))
			o.Expect(checkPO).To(o.ContainSubstring("kube-rbac-proxy-web"))

			exutil.By("check ThanosRuler, new configs added")
			output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("ThanosRuler", "user-workload", "-n", "openshift-user-workload-monitoring", "-ojsonpath={.spec.containers[?(@.name==\"kube-rbac-proxy-web\")].args}").Output()
			o.Expect(output).To(o.ContainSubstring("config-file=/etc/kube-rbac-proxy/config.yaml"))
			o.Expect(output).To(o.ContainSubstring("tls-cert-file=/etc/tls/private/tls.crt"))
			o.Expect(output).To(o.ContainSubstring("tls-private-key-file=/etc/tls/private/tls.key"))
		})

		//author: tagao@redhat.com
		g.It("Author:tagao-High-73213-Enable controller id for CMO Prometheus resources [Serial]", func() {
			var (
				uwmEnableAlertmanager = filepath.Join(monitoringBaseDir, "uwm-enableAlertmanager.yaml")
			)
			exutil.By("delete uwm-config/cm-config at the end of a serial case")
			defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
			defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

			exutil.By("enable alertmanager for uwm")
			createResourceFromYaml(oc, "openshift-user-workload-monitoring", uwmEnableAlertmanager)

			exutil.By("wait for all pods ready")
			exutil.AssertPodToBeReady(oc, "prometheus-user-workload-0", "openshift-user-workload-monitoring")
			exutil.AssertPodToBeReady(oc, "alertmanager-user-workload-0", "openshift-user-workload-monitoring")
			exutil.AssertPodToBeReady(oc, "thanos-ruler-user-workload-0", "openshift-user-workload-monitoring")

			exutil.By("check alertmanager controller-id")
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("alertmanager", "main", "-n", "openshift-monitoring", "-ojsonpath={.metadata.annotations}").Output()
			o.Expect(output).To(o.ContainSubstring(`"operator.prometheus.io/controller-id":"openshift-monitoring/prometheus-operator"`))
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("check UWM alertmanager controller-id")
			output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("alertmanager", "user-workload", "-n", "openshift-user-workload-monitoring", "-ojsonpath={.metadata.annotations}").Output()
			o.Expect(output).To(o.ContainSubstring(`"operator.prometheus.io/controller-id":"openshift-user-workload-monitoring/prometheus-operator"`))
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("check prometheus k8s controller-id")
			output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheus", "k8s", "-n", "openshift-monitoring", "-ojsonpath={.metadata.annotations}").Output()
			o.Expect(output).To(o.ContainSubstring(`"operator.prometheus.io/controller-id":"openshift-monitoring/prometheus-operator"`))
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("check prometheus-operator deployment controller-id")
			output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deploy", "prometheus-operator", "-n", "openshift-monitoring", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"prometheus-operator\")].args}").Output()
			o.Expect(output).To(o.ContainSubstring(`"--controller-id=openshift-monitoring/prometheus-operator"`))
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("check UWM prometheus-operator deployment controller-id")
			output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deploy", "prometheus-operator", "-n", "openshift-user-workload-monitoring", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"prometheus-operator\")].args}").Output()
			o.Expect(output).To(o.ContainSubstring(`"--controller-id=openshift-user-workload-monitoring/prometheus-operator"`))
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("check UWM prometheus user-workload controller-id")
			output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheus", "user-workload", "-n", "openshift-user-workload-monitoring", "-ojsonpath={.metadata.annotations}").Output()
			o.Expect(output).To(o.ContainSubstring(`"operator.prometheus.io/controller-id":"openshift-user-workload-monitoring/prometheus-operator"`))
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("check ThanosRuler user-workload controller-id")
			output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("ThanosRuler", "user-workload", "-n", "openshift-user-workload-monitoring", "-ojsonpath={.metadata.annotations}").Output()
			o.Expect(output).To(o.ContainSubstring(`"operator.prometheus.io/controller-id":"openshift-user-workload-monitoring/prometheus-operator"`))
			o.Expect(err).NotTo(o.HaveOccurred())
		})

		//author: juzhao@redhat.com
		g.It("Author:juzhao-Low-73684-UWM statefulset should not lack serviceName", func() {
			exutil.By("check spec.serviceName for UWM statefulset")
			cmd := "-ojsonpath={.spec.serviceName}}"
			checkYamlconfig(oc, "openshift-user-workload-monitoring", "statefulset", "prometheus-user-workload", cmd, "prometheus-operated", true)
			checkYamlconfig(oc, "openshift-user-workload-monitoring", "statefulset", "thanos-ruler-user-workload", cmd, "thanos-ruler-operated", true)
		})

		//author: tagao@redhat.com
		g.It("Author:tagao-Medium-73734-Add ownership annotation for certificates [Serial]", func() {
			var (
				uwmEnableAlertmanager = filepath.Join(monitoringBaseDir, "uwm-enableAlertmanager.yaml")
			)
			exutil.By("delete uwm-config/cm-config at the end of a serial case")
			defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
			defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

			exutil.By("enable alertmanager for uwm")
			createResourceFromYaml(oc, "openshift-user-workload-monitoring", uwmEnableAlertmanager)

			exutil.By("check annotations added to the CM under the namespace openshift-monitoring")
			cmd := "-ojsonpath={.metadata.annotations}"
			checkYamlconfig(oc, "openshift-monitoring", "cm", "alertmanager-trusted-ca-bundle", cmd, `"openshift.io/owning-component":"Monitoring"`, true)
			checkYamlconfig(oc, "openshift-monitoring", "cm", "kubelet-serving-ca-bundle", cmd, `"openshift.io/owning-component":"Monitoring"`, true)
			checkYamlconfig(oc, "openshift-monitoring", "cm", "prometheus-trusted-ca-bundle", cmd, `"openshift.io/owning-component":"Monitoring"`, true)
			telemeterPod, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-l", "app.kubernetes.io/name=telemeter-client", "-n", "openshift-monitoring").Output()
			if strings.Contains(telemeterPod, "telemeter-client") {
				checkYamlconfig(oc, "openshift-monitoring", "cm", "telemeter-trusted-ca-bundle", cmd, `"openshift.io/owning-component":"Monitoring"`, true)
			}

			exutil.By("check annotations added to the CM under the namespace openshift-user-workload-monitoring")
			checkYamlconfig(oc, "openshift-user-workload-monitoring", "cm", "prometheus-user-workload-trusted-ca-bundle", cmd, `"openshift.io/owning-component":"Monitoring"`, true)
			checkYamlconfig(oc, "openshift-user-workload-monitoring", "cm", "alertmanager-trusted-ca-bundle", cmd, `"openshift.io/owning-component":"Monitoring"`, true)
		})

		//author: juzhao@redhat.com
		g.It("Author:juzhao-Medium-75489-Set scrape.timestamp tolerance for UWM prometheus", func() {
			exutil.By("confirm for UWM prometheus created")
			err := wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 180*time.Second, false, func(context.Context) (bool, error) {
				prometheus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheus", "user-workload", "-n", "openshift-user-workload-monitoring").Output()
				if err != nil || strings.Contains(prometheus, "not found") {
					return false, nil
				}
				return true, nil
			})
			exutil.AssertWaitPollNoErr(err, "UWM prometheus not created")

			exutil.By("check for UWM prometheus scrape.timestamp tolerance")
			cmd := `-ojsonpath={.spec.additionalArgs[?(@.name=="scrape.timestamp-tolerance")]}`
			checkYamlconfig(oc, "openshift-user-workload-monitoring", "prometheus", "user-workload", cmd, `"value":"15ms"`, true)

			exutil.By("check settings in UWM prometheus pods")
			podNames, err := exutil.GetAllPodsWithLabel(oc, "openshift-user-workload-monitoring", "app.kubernetes.io/name=prometheus")
			o.Expect(err).NotTo(o.HaveOccurred())
			for _, pod := range podNames {
				cmd := "-ojsonpath={.spec.containers[?(@.name==\"prometheus\")].args}"
				checkYamlconfig(oc, "openshift-user-workload-monitoring", "pod", pod, cmd, `--scrape.timestamp-tolerance=15ms`, true)
			}
		})

		// author: tagao@redhat.com
		g.It("Author:tagao-High-75384-cross-namespace rules for user-workload monitoring [Serial]", func() {
			var (
				example_cross_ns_alert     = filepath.Join(monitoringBaseDir, "example_cross_ns_alert.yaml")
				disable_uwm_cross_ns_rules = filepath.Join(monitoringBaseDir, "disable_uwm_cross_ns_rules.yaml")
			)
			exutil.By("delete uwm-config/cm-config at the end of the case")
			defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
			defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

			exutil.By("Create a user-monitoring-shared namespace and deploy PrometheusRule")
			oc.SetupProject()
			ns := oc.Namespace()
			err := oc.AsAdmin().WithoutNamespace().Run("label").Args("namespace", ns, "pod-security.kubernetes.io/enforce=restricted", "--overwrite=true").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("ns", "ns-monitoring-75384", "--ignore-not-found").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("create").Args("namespace", "ns-monitoring-75384").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("namespace", "ns-monitoring-75384", "pod-security.kubernetes.io/enforce=restricted", "--overwrite=true").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			createResourceFromYaml(oc, "ns-monitoring-75384", example_cross_ns_alert)

			exutil.By("check namespace have expect label")
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("ns", ns, "-ojsonpath={.metadata.labels}").Output()
			o.Expect(output).To(o.ContainSubstring(`"pod-security.kubernetes.io/enforce":"restricted"`))
			o.Expect(err).NotTo(o.HaveOccurred())
			output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("ns", "ns-monitoring-75384", "-ojsonpath={.metadata.labels}").Output()
			o.Expect(output).To(o.ContainSubstring(`"pod-security.kubernetes.io/enforce":"restricted"`))
			o.Expect(err).NotTo(o.HaveOccurred())

			exutil.By("check metrics")
			token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
			checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="TestAlert1", namespace="ns-monitoring-75384"}'`, token, `"namespace":"ns-monitoring-75384"`, 2*uwmLoadTime)
			checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="TestAlert1", namespace="`+ns+`"}'`, token, `"namespace":"`+ns+`"`, 2*uwmLoadTime)

			exutil.By("disable the feature")
			createResourceFromYaml(oc, "openshift-monitoring", disable_uwm_cross_ns_rules)

			exutil.By("check the alert should not share across the namespace")
			checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="TestAlert1", namespace="`+ns+`"}'`, token, `"result":[]`, 2*uwmLoadTime)
		})
	})

	//author: tagao@redhat.com
	g.It("Author:tagao-Low-30088-User can not deploy ThanosRuler CRs in user namespaces [Serial]", func() {
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("create namespace as a common user (non-admin)")
		oc.SetupProject()
		ns := oc.Namespace()

		exutil.By("check ThanosRuler can not be created")
		currentUser, _ := oc.Run("whoami").Args("").Output()
		e2e.Logf("current user is: %v", currentUser)
		queryErr := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 60*time.Second, true, func(context.Context) (bool, error) {
			permissionCheck, _ := oc.WithoutNamespace().Run("auth").Args("can-i", "create", "thanosrulers", "--as="+currentUser, "-n", ns).Output()
			if !strings.Contains(permissionCheck, "yes") {
				return true, nil
			}
			return false, nil
		})
		exutil.AssertWaitPollNoErr(queryErr, "permissionCheck failed to contain \"no\"")
	})

	// The test is already covered in pkg/manifests/config_test.go::TestLoadEnforcedBodySizeLimit
	//author: tagao@redhat.com
	/* 	g.It("Author:tagao-NonPreRelease-Longduration-Medium-49191-Enforce body_size_limit [Serial]", func() {
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("set `enforcedBodySizeLimit` to 0, and check from the k8s pod")
		patchAndCheckBodySizeLimit(oc, "0", "0")

		exutil.By("set `enforcedBodySizeLimit` to a invalid value, and check from the k8s pod")
		patchAndCheckBodySizeLimit(oc, "20MiBPS", "")

		exutil.By("set `enforcedBodySizeLimit` to 1MB to trigger PrometheusScrapeBodySizeLimitHit alert, and check from the k8s pod")
		patchAndCheckBodySizeLimit(oc, "1MB", "1MB")

		exutil.By("check PrometheusScrapeBodySizeLimitHit alert is triggered")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="PrometheusScrapeBodySizeLimitHit"}'`, token, "PrometheusScrapeBodySizeLimitHit", 5*uwmLoadTime)

		exutil.By("set `enforcedBodySizeLimit` to 40MB, and check from the k8s pod")
		patchAndCheckBodySizeLimit(oc, "40MB", "40MB")

		exutil.By("check from alert, should not have enforcedBodySizeLimit")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="PrometheusScrapeBodySizeLimitHit"}'`, token, `"result":[]`, 5*uwmLoadTime)

		exutil.By("set `enforcedBodySizeLimit` to automatic, and check from the k8s pod")
		patchAndCheckBodySizeLimit(oc, "automatic", "body_size_limit")

		exutil.By("check from alert, should not have enforcedBodySizeLimit")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="PrometheusScrapeBodySizeLimitHit"}'`, token, `"result":[]`, 5*uwmLoadTime)
	}) */

	// The test is already covered in pkg/manifests/manifests_test.go::TestNodeExporterCollectorSettings
	//author: tagao@redhat.com
	/* 	g.It("Author:tagao-High-60485-check On/Off switch of netdev Collector in Node Exporter [Serial]", func() {
		var (
			disableNetdev = filepath.Join(monitoringBaseDir, "disableNetdev.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check netdev Collector is enabled by default")
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--collector.netdev"))

		exutil.By("check netdev metrics in prometheus k8s pod")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="netdev"}'`, token, `"collector":"netdev"`, uwmLoadTime)

		exutil.By("disable netdev in CMO")
		createResourceFromYaml(oc, "openshift-monitoring", disableNetdev)

		exutil.By("check netdev metrics in prometheus k8s pod again, should not have related metrics")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="netdev"}'`, token, `"result":[]`, 3*uwmLoadTime)

		exutil.By("check netdev in daemonset")
		output2, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output2).To(o.ContainSubstring("--no-collector.netdev"))
	}) */

	// The test is already covered in pkg/manifests/manifests_test.go::TestNodeExporterCollectorSettings
	//author: tagao@redhat.com
	/* 	g.It("Author:tagao-High-59521-check On/Off switch of cpufreq Collector in Node Exporter [Serial]", func() {
		var (
			enableCpufreq = filepath.Join(monitoringBaseDir, "enableCpufreq.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check cpufreq Collector is disabled by default")
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--no-collector.cpufreq"))

		exutil.By("check cpufreq metrics in prometheus k8s pod, should not have related metrics")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="cpufreq"}'`, token, `"result":[]`, uwmLoadTime)

		exutil.By("enable cpufreq in CMO")
		createResourceFromYaml(oc, "openshift-monitoring", enableCpufreq)

		exutil.By("check cpufreq metrics in prometheus k8s pod again")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="cpufreq"}'`, token, `"collector":"cpufreq"`, 3*uwmLoadTime)

		exutil.By("check cpufreq in daemonset")
		output2, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output2).To(o.ContainSubstring("--collector.cpufreq"))
	}) */

	// The test is already covered in pkg/manifests/manifests_test.go::TestNodeExporterCollectorSettings
	//author: tagao@redhat.com
	/* 	g.It("Author:tagao-High-60480-check On/Off switch of tcpstat Collector in Node Exporter [Serial]", func() {
		var (
			enableTcpstat = filepath.Join(monitoringBaseDir, "enableTcpstat.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check tcpstat Collector is disabled by default")
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--no-collector.tcpstat"))

		exutil.By("check tcpstat metrics in prometheus k8s pod, should not have related metrics")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="tcpstat"}'`, token, `"result":[]`, uwmLoadTime)

		exutil.By("enable tcpstat in CMO")
		createResourceFromYaml(oc, "openshift-monitoring", enableTcpstat)

		exutil.By("check tcpstat metrics in prometheus k8s pod again")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="tcpstat"}'`, token, `"collector":"tcpstat"`, 3*uwmLoadTime)

		exutil.By("check tcpstat in daemonset")
		output2, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output2).To(o.ContainSubstring("--collector.tcpstat"))
	}) */

	// The test is already covered in pkg/manifests/manifests_test.go::TestNodeExporterCollectorSettings
	//author: tagao@redhat.com
	/* 	g.It("Author:tagao-High-60582-check On/Off switch of buddyinfo Collector in Node Exporter [Serial]", func() {
		var (
			enableBuddyinfo = filepath.Join(monitoringBaseDir, "enableBuddyinfo.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check buddyinfo Collector is disabled by default")
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--no-collector.buddyinfo"))

		exutil.By("check buddyinfo metrics in prometheus k8s pod, should not have related metrics")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="buddyinfo"}'`, token, `"result":[]`, uwmLoadTime)

		exutil.By("enable buddyinfo in CMO")
		createResourceFromYaml(oc, "openshift-monitoring", enableBuddyinfo)

		exutil.By("check buddyinfo metrics in prometheus k8s pod again")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="buddyinfo"}'`, token, `"collector":"buddyinfo"`, 3*uwmLoadTime)

		exutil.By("check buddyinfo in daemonset")
		output2, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output2).To(o.ContainSubstring("--collector.buddyinfo"))
	}) */

	//author: juzhao@redhat.com
	g.It("Author:juzhao-Medium-59986-Allow to configure secrets in alertmanager component [Serial]", func() {
		var (
			alertmanagerSecret      = filepath.Join(monitoringBaseDir, "alertmanager-secret.yaml")
			alertmanagerSecretCM    = filepath.Join(monitoringBaseDir, "alertmanager-secret-cm.yaml")
			alertmanagerSecretUwmCM = filepath.Join(monitoringBaseDir, "alertmanager-secret-uwm-cm.yaml")
		)
		exutil.By("delete secrets/user-workload-monitoring-config/cluster-monitoring-config configmap at the end of a serial case")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("secret", "test-secret", "-n", "openshift-monitoring").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("secret", "slack-api-token", "-n", "openshift-monitoring").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("secret", "test-secret", "-n", "openshift-user-workload-monitoring").Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("secret", "slack-api-token", "-n", "openshift-user-workload-monitoring").Execute()
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("create alertmanager secret in openshift-monitoring")
		createResourceFromYaml(oc, "openshift-monitoring", alertmanagerSecret)

		exutil.By("enabled UWM and configure alertmanager secret setting in cluster-monitoring-config configmap")
		createResourceFromYaml(oc, "openshift-monitoring", alertmanagerSecretCM)

		exutil.By("check if the secrets are mounted to alertmanager pod")
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
		checkConfigInPod(oc, "openshift-monitoring", "alertmanager-main-0", "alertmanager", "ls /etc/alertmanager/secrets/", "test-secret")
		checkConfigInPod(oc, "openshift-monitoring", "alertmanager-main-0", "alertmanager", "ls /etc/alertmanager/secrets/", "slack-api-token")

		exutil.By("create the same alertmanager secret in openshift-user-workload-monitoring")
		createResourceFromYaml(oc, "openshift-user-workload-monitoring", alertmanagerSecret)

		exutil.By("configure alertmanager secret setting in user-workload-monitoring-config configmap")
		createResourceFromYaml(oc, "openshift-user-workload-monitoring", alertmanagerSecretUwmCM)

		exutil.By("check if the secrets are mounted to UWM alertmanager pod")
		exutil.AssertAllPodsToBeReady(oc, "openshift-user-workload-monitoring")
		checkConfigInPod(oc, "openshift-user-workload-monitoring", "alertmanager-user-workload-0", "alertmanager", "ls /etc/alertmanager/secrets/", "test-secret")
		checkConfigInPod(oc, "openshift-user-workload-monitoring", "alertmanager-user-workload-0", "alertmanager", "ls /etc/alertmanager/secrets/", "slack-api-token")
	})

	// The test is already covered in pkg/manifests/manifests_test.go::TestNodeExporterGeneralSettings
	//author: tagao@redhat.com
	/* 	g.It("Author:tagao-Low-60534-check gomaxprocs setting of Node Exporter in CMO [Serial]", func() {
		var (
			setGomaxprocsTo1 = filepath.Join(monitoringBaseDir, "setGomaxprocsTo1.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check default gomaxprocs value is 0")
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset", "node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--runtime.gomaxprocs=0"))

		exutil.By("set gomaxprocs value to 1")
		createResourceFromYaml(oc, "openshift-monitoring", setGomaxprocsTo1)

		exutil.By("check gomaxprocs value in daemonset")
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
		cmd := "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}"
		checkYamlconfig(oc, "openshift-monitoring", "daemonset", "node-exporter", cmd, "--runtime.gomaxprocs=1", true)
	}) */

	// The test is already covered in pkg/manifests/manifests_test.go::TestNodeExporterCollectorSettings
	//author: tagao@redhat.com
	/* 	g.It("Author:tagao-High-60486-check On/Off switch of netclass Collector and netlink backend in Node Exporter [Serial]", func() {
		var (
			disableNetclass = filepath.Join(monitoringBaseDir, "disableNetclass.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check netclass Collector is enabled by default, so as netlink")
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
		//oc -n openshift-monitoring get daemonset.apps/node-exporter -ojsonpath='{.spec.template.spec.containers[?(@.name=="node-exporter")].args}'
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--collector.netclass"))
		o.Expect(output).To(o.ContainSubstring("--collector.netclass.netlink"))

		exutil.By("check netclass metrics in prometheus k8s pod")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="netclass"}'`, token, `"collector":"netclass"`, uwmLoadTime)

		exutil.By("disable netclass in CMO")
		createResourceFromYaml(oc, "openshift-monitoring", disableNetclass)

		exutil.By("check netclass metrics in prometheus k8s pod again, should not have related metrics")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="netclass"}'`, token, `"result":[]`, 3*uwmLoadTime)

		exutil.By("check netclass/netlink in daemonset")
		output, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--no-collector.netclass"))
		o.Expect(output).NotTo(o.ContainSubstring("--collector.netclass.netlink"))
	}) */

	// The test is already covered in pkg/manifests/manifests_test.go::TestNodeExporterCollectorSettings
	//author: tagao@redhat.com
	/* 	g.It("Author:tagao-High-63659-check On/Off switch of ksmd Collector in Node Exporter [Serial]", func() {
		var (
			enableKsmd = filepath.Join(monitoringBaseDir, "enableKsmd.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check ksmd Collector is disabled by default")
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--no-collector.ksmd"))

		exutil.By("check ksmd metrics in prometheus k8s pod, should not have related metrics")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="ksmd"}'`, token, `"result":[]`, uwmLoadTime)

		exutil.By("enable ksmd in CMO")
		createResourceFromYaml(oc, "openshift-monitoring", enableKsmd)

		exutil.By("check ksmd metrics in prometheus k8s pod again")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="ksmd"}'`, token, `"collector":"ksmd"`, 3*uwmLoadTime)

		exutil.By("check ksmd in daemonset")
		output, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--collector.ksmd"))
	}) */

	// The test is already covered in pkg/manifests/manifests_test.go::TestMonitoringPluginConfig
	// author: tagao@redhat.com
	/* 	g.It("Author:tagao-LEVEL0-High-64537-CMO deploys monitoring console-plugin [Serial]", func() {
		var (
			monitoringPluginConfig = filepath.Join(monitoringBaseDir, "monitoringPlugin-config.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("skip the case if console CO is absent")
		checkCO, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		if !strings.Contains(checkCO, "console") {
			g.Skip("This case is not executable when console CO is absent")
		}

		exutil.By("apply monitoringPlugin config and check config applied")
		createResourceFromYaml(oc, "openshift-monitoring", monitoringPluginConfig)
		//check new config takes effect
		cmd := "-ojsonpath={.spec.template.spec.containers[].resources}"
		checkYamlconfig(oc, "openshift-monitoring", "deployment", "monitoring-plugin", cmd, `{"limits":{"cpu":"30m","memory":"120Mi"},"requests":{"cpu":"15m","memory":"60Mi"}}`, true)

		exutil.By("check monitoring-plugin ConsolePlugin/PodDisruptionBudget/ServiceAccount/Service are exist")
		resourceNames := []string{"ConsolePlugin", "ServiceAccount", "Service"}
		for _, resource := range resourceNames {
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(resource, "monitoring-plugin", "-n", "openshift-monitoring").Output()
			o.Expect(output).To(o.ContainSubstring("monitoring-plugin"))
			o.Expect(err).NotTo(o.HaveOccurred())
		}
		//SNO cluster do not have PDB under openshift-monitoring
		//hypershift-hosted cluster do not have master node
		checkPodDisruptionBudgetIfNotSNO(oc)

		exutil.By("wait for monitoring-plugin pod to be ready")
		getDeploymentReplicas(oc, "openshift-monitoring", "monitoring-plugin")
		waitForPodsToMatchReplicas(oc, "openshift-monitoring", "monitoring-plugin", "app.kubernetes.io/component=monitoring-plugin")

		exutil.By("check monitoring-plugin pod config")
		monitoringPluginPodNames, err := getAllRunningPodsWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/component=monitoring-plugin")
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("monitoringPluginPodNames: %v", monitoringPluginPodNames)
		for _, pod := range monitoringPluginPodNames {
			exutil.AssertPodToBeReady(oc, pod, "openshift-monitoring")
			cmd := "-ojsonpath={.spec.nodeSelector}"
			checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, `{"node-role.kubernetes.io/worker":""}`, true)
			cmd = "-ojsonpath={.spec.topologySpreadConstraints}"
			checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, `{"maxSkew":1,"topologyKey":"kubernetes.io/hostname","whenUnsatisfiable":"DoNotSchedule"}`, true)
			cmd = "-ojsonpath={.spec.tolerations}"
			checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, `{"operator":"Exists"}`, true)
			cmd = "-ojsonpath={.spec.containers[].resources}"
			checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, `"requests":{"cpu":"15m","memory":"60Mi"}`, true)
			checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, `"limits":{"cpu":"30m","memory":"120Mi"}`, true)
		}
	}) */

	// The test is already covered in pkg/manifests/manifests_test.go::TestNodeExporterCollectorSettings
	// author: tagao@redhat.com
	/* 	g.It("Author:tagao-High-63657-check On/Off switch of systemd Collector in Node Exporter [Serial]", func() {
		var (
			enableSystemdUnits = filepath.Join(monitoringBaseDir, "enableSystemdUnits.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check systemd Collector is disabled by default")
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--no-collector.systemd"))

		exutil.By("check systemd metrics in prometheus k8s pod, should not have related metrics")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="systemd"}'`, token, `"result":[]`, uwmLoadTime)

		exutil.By("enable systemd and units in CMO")
		createResourceFromYaml(oc, "openshift-monitoring", enableSystemdUnits)

		exutil.By("check systemd related metrics in prometheus k8s pod again")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="systemd"}'`, token, `"collector":"systemd"`, 3*uwmLoadTime)
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_systemd_system_running'`, token, `"node_systemd_system_running"`, 3*uwmLoadTime)
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_systemd_timer_last_trigger_seconds'`, token, `"node_systemd_timer_last_trigger_seconds"`, 3*uwmLoadTime)
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_systemd_units'`, token, `"node_systemd_units"`, 3*uwmLoadTime)
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_systemd_version'`, token, `"node_systemd_version"`, 3*uwmLoadTime)
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_systemd_unit_state'`, token, `"node_systemd_unit_state"`, 3*uwmLoadTime)

		exutil.By("check systemd in daemonset")
		output, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--collector.systemd"))
		o.Expect(output).To(o.ContainSubstring("--collector.systemd.unit-include=^(network.+|nss.+|logrotate.timer)$"))
	}) */

	// The test is already covered in pkg/manifests/manifests_test.go::TestNodeExporterCollectorSettings
	// author: tagao@redhat.com
	/* 	g.It("Author:tagao-High-63658-check On/Off switch of mountstats Collector in Node Exporter [Serial]", func() {
		var (
			enableMountstats    = filepath.Join(monitoringBaseDir, "enableMountstats.yaml")
			enableMountstatsNFS = filepath.Join(monitoringBaseDir, "enableMountstats_nfs.yaml")
		)
		exutil.By("delete uwm-config/cm-config and pvcs at the end of the case")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("pvc", "-l", "app.kubernetes.io/name=prometheus", "-n", "openshift-monitoring").Execute()
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check mountstats collector is disabled by default")
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--no-collector.mountstats"))

		exutil.By("check mountstats metrics in prometheus k8s pod, should not have related metrics")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="mountstats"}'`, token, `"result":[]`, uwmLoadTime)

		exutil.By("enable mountstats in CMO")
		createResourceFromYaml(oc, "openshift-monitoring", enableMountstats)

		exutil.By("check mountstats metrics in prometheus k8s pod again")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="mountstats"}'`, token, `"collector":"mountstats"`, 3*uwmLoadTime)

		exutil.By("check mountstats in daemonset")
		output, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--collector.mountstats"))

		exutil.By("check nfs metrics if need")
		output, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("sc").Output()
		if strings.Contains(output, "nfs") {
			createResourceFromYaml(oc, "openshift-monitoring", enableMountstatsNFS)
			exutil.AssertPodToBeReady(oc, "prometheus-k8s-0", "openshift-monitoring")
			checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_mountstats_nfs_read_bytes_total'`, token, `"__name__":"node_mountstats_nfs_read_bytes_total"`, 3*uwmLoadTime)
			checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_mountstats_nfs_write_bytes_total'`, token, `"__name__":"node_mountstats_nfs_write_bytes_total"`, 3*uwmLoadTime)
			checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_mountstats_nfs_operations_requests_total'`, token, `"__name__":"node_mountstats_nfs_operations_requests_total"`, 3*uwmLoadTime)
		} else {
			e2e.Logf("no need to check nfs metrics for this env")
		}
	}) */

	// The test is already covered in pkg/manifests/manifests_test.go::TestNodeExporterCollectorSettings and pkg/manifests/manifests_test.go::TestSetArg
	// author: tagao@redhat.com
	/* 	g.It("Author:tagao-Medium-64868-netclass/netdev device configuration [Serial]", func() {
		var (
			ignoredNetworkDevices = filepath.Join(monitoringBaseDir, "ignoredNetworkDevices-lo.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check netclass/netdev device configuration")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--collector.netclass.ignored-devices=^(veth.*|[a-f0-9]{15}|enP.*|ovn-k8s-mp[0-9]*|br-ex|br-int|br-ext|br[0-9]*|tun[0-9]*|cali[a-f0-9]*)$"))
		o.Expect(output).To(o.ContainSubstring("--collector.netdev.device-exclude=^(veth.*|[a-f0-9]{15}|enP.*|ovn-k8s-mp[0-9]*|br-ex|br-int|br-ext|br[0-9]*|tun[0-9]*|cali[a-f0-9]*)$"))

		exutil.By("Get token of SA prometheus-k8s")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

		exutil.By("check lo devices exist, and able to see related metrics")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=group by(device) (node_network_info)'`, token, `"device":"lo"`, uwmLoadTime)

		exutil.By("modify cm to ignore lo devices")
		createResourceFromYaml(oc, "openshift-monitoring", ignoredNetworkDevices)
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")

		exutil.By("check metrics again, should not see lo device metrics")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_network_info{device="lo"}'`, token, `"result":[]`, 3*uwmLoadTime)

		exutil.By("check netclass/netdev device configuration, no lo devices")
		output, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--collector.netclass.ignored-devices=^(lo)$"))
		o.Expect(output).To(o.ContainSubstring("--collector.netdev.device-exclude=^(lo)$"))

		exutil.By("modify cm to ignore all devices")
		// % oc -n openshift-monitoring patch cm cluster-monitoring-config -p '{"data": {"config.yaml": "nodeExporter:\n ignoredNetworkDevices: [.*]"}}' --type=merge
		err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("cm", "cluster-monitoring-config", "-p", `{"data": {"config.yaml": "nodeExporter:\n ignoredNetworkDevices: [.*]"}}`, "--type=merge", "-n", "openshift-monitoring").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("check metrics again, should not see all device metrics")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=group by(device) (node_network_info)'`, token, `"result":[]`, 3*uwmLoadTime)

		exutil.By("check netclass/netdev device configuration again")
		output, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--collector.netclass.ignored-devices=^(.*)$"))
		o.Expect(output).To(o.ContainSubstring("--collector.netdev.device-exclude=^(.*)$"))
	}) */

	// The test is already covered in pkg/manifests/manifests_test.go::TestThanosQuerierConfiguration
	// author: tagao@redhat.com
	/* 	g.It("Author:tagao-LEVEL0-Medium-64296-disable CORS headers on Thanos querier [Serial]", func() {
		var (
			enableCORS = filepath.Join(monitoringBaseDir, "enableCORS.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check the default enableCORS value is false")
		// oc -n openshift-monitoring get deployments.apps thanos-querier -o jsonpath='{.spec.template.spec.containers[?(@.name=="thanos-query")].args}' |jq
		thanosQueryArgs, getArgsErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("deployments/thanos-querier", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"thanos-query\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(getArgsErr).NotTo(o.HaveOccurred(), "Failed to get thanos-query container args definition")
		o.Expect(thanosQueryArgs).To(o.ContainSubstring("--web.disable-cors"))

		exutil.By("set enableCORS as true")
		createResourceFromYaml(oc, "openshift-monitoring", enableCORS)
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")

		exutil.By("check the config again")
		cmd := "-ojsonpath={.spec.template.spec.containers[?(@.name==\"thanos-query\")].args}"
		checkYamlconfig(oc, "openshift-monitoring", "deployments", "thanos-querier", cmd, `--web.disable-cors`, false)
	}) */

	// This test is already covered in test/e2e/alertmanager_test.go::TestAlertmanagerDisabling
	//author: tagao@redhat.com
	/* 	g.It("Author:tagao-Medium-43106-disable Alertmanager deployment[Serial]", func() {
		var (
			disableAlertmanager = filepath.Join(monitoringBaseDir, "disableAlertmanager.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("disable alertmanager in CMO config")
		createResourceFromYaml(oc, "openshift-monitoring", disableAlertmanager)
		exutil.AssertAllPodsToBeReady(oc, "openshift-user-workload-monitoring")

		// this step is aim to give time let CMO removing alertmanager resources
		exutil.By("confirm alertmanager is down")
		checkPodDeleted(oc, "openshift-monitoring", "alertmanager=main", "alertmanager")

		exutil.By("check alertmanager resources are removed")
		err := wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 90*time.Second, false, func(context.Context) (bool, error) {
			resourceNames := []string{"route", "servicemonitor", "serviceaccounts", "statefulset", "services", "endpoints", "alertmanagers", "prometheusrules", "clusterrolebindings", "roles"}
			for _, resource := range resourceNames {
				output, outputErr := oc.AsAdmin().WithoutNamespace().Run("get").Args(resource, "-n", "openshift-monitoring").Output()
				if outputErr != nil || strings.Contains(output, "alertmanager") {
					return false, nil
				}
			}
			return true, nil
		})
		exutil.AssertWaitPollNoErr(err, "one or more alertmanager resources not removed yet")

		exutil.By("check on clusterroles")
		clusterroles, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterroles", "-l", "app.kubernetes.io/part-of=openshift-monitoring").Output()
		o.Expect(clusterroles).NotTo(o.ContainSubstring("alertmanager"))
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("check on configmaps")
		checkCM, _ := exec.Command("bash", "-c", `oc -n openshift-monitoring get cm -l app.kubernetes.io/managed-by=cluster-monitoring-operator | grep alertmanager`).Output()
		e2e.Logf("check result is: %v", checkCM)
		o.Expect(checkCM).NotTo(o.ContainSubstring("alertmanager-trusted-ca-bundle"))

		exutil.By("check on rolebindings")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("rolebindings", "-n", "openshift-monitoring").Output()
		o.Expect(output).NotTo(o.ContainSubstring("alertmanager-prometheusk8s"))
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("Get token of SA prometheus-k8s")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

		exutil.By("check Watchdog alert exist")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertstate="firing",alertname="Watchdog"}'`, token, `"alertname":"Watchdog"`, uwmLoadTime)
	}) */

	// author: juzhao@redhat.com
	g.It("Author:juzhao-Medium-66736-add option to specify resource requests and limits for components [Serial]", func() {
		var (
			clusterResources = filepath.Join(monitoringBaseDir, "cluster_resources.yaml")
			uwmResources     = filepath.Join(monitoringBaseDir, "uwm_resources.yaml")
		)
		exutil.By("delete user-workload-monitoring-config/cluster-monitoring-config configmap at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		createResourceFromYaml(oc, "openshift-monitoring", clusterResources)
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")

		exutil.By("by default there is not resources.limits setting for the components, check the result for kube_pod_container_resource_limits of node-exporter pod to see if the setting loaded to components, same for other components")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=kube_pod_container_resource_limits{container="node-exporter",namespace="openshift-monitoring"}'`, token, `"pod":"node-exporter-`, 3*uwmLoadTime)

		exutil.By("check the resources.requests and resources.limits setting loaded to node-exporter daemonset")
		// oc -n openshift-monitoring get daemonset node-exporter -o jsonpath='{.spec.template.spec.containers[?(@.name=="node-exporter")].resources.requests}'
		result, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].resources.requests}", "-n", "openshift-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get node-exporter container resources.requests setting")
		o.Expect(result).To(o.ContainSubstring(`"cpu":"10m","memory":"40Mi"`))

		// oc -n openshift-monitoring get daemonset node-exporter -o jsonpath='{.spec.template.spec.containers[?(@.name=="node-exporter")].resources.limits}'
		result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].resources.limits}", "-n", "openshift-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get node-exporter container resources.limits setting")
		o.Expect(result).To(o.ContainSubstring(`"cpu":"20m","memory":"100Mi"`))

		exutil.By("check the resources.requests and resources.limits take effect for kube-state-metrics")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=kube_pod_container_resource_limits{container="kube-state-metrics",namespace="openshift-monitoring"}'`, token, `"pod":"kube-state-metrics-`, 3*uwmLoadTime)
		result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment/kube-state-metrics", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"kube-state-metrics\")].resources.requests}", "-n", "openshift-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get kube-state-metrics container resources.requests setting")
		o.Expect(result).To(o.ContainSubstring(`"cpu":"3m","memory":"100Mi"`))

		result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment/kube-state-metrics", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"kube-state-metrics\")].resources.limits}", "-n", "openshift-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get kube-state-metrics container resources.limits setting")
		o.Expect(result).To(o.ContainSubstring(`"cpu":"10m","memory":"200Mi"`))

		exutil.By("check the resources.requests and resources.limits take effect for openshift-state-metrics")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=kube_pod_container_resource_limits{container="openshift-state-metrics",namespace="openshift-monitoring"}'`, token, `"pod":"openshift-state-metrics-`, 3*uwmLoadTime)
		result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment/openshift-state-metrics", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"openshift-state-metrics\")].resources.requests}", "-n", "openshift-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get openshift-state-metrics container resources.requests setting")
		o.Expect(result).To(o.ContainSubstring(`"cpu":"2m","memory":"40Mi"`))

		result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment/openshift-state-metrics", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"openshift-state-metrics\")].resources.limits}", "-n", "openshift-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get openshift-state-metrics container resources.limits setting")
		o.Expect(result).To(o.ContainSubstring(`"cpu":"20m","memory":"100Mi"`))

		exutil.By("check the resources.requests and resources.limits take effect for metrics-server")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=kube_pod_container_resource_limits{container="metrics-server",namespace="openshift-monitoring"}'`, token, `"pod":"metrics-server-`, 3*uwmLoadTime)
		result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment/metrics-server", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"metrics-server\")].resources.requests}", "-n", "openshift-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get metrics-server container resources.requests setting")
		o.Expect(result).To(o.ContainSubstring(`"cpu":"2m","memory":"80Mi"`))

		result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment/metrics-server", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"metrics-server\")].resources.limits}", "-n", "openshift-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get metrics-server container resources.limits setting")
		o.Expect(result).To(o.ContainSubstring(`"cpu":"10m","memory":"100Mi"`))

		exutil.By("check the resources.requests and resources.limits take effect for prometheus-operator")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=kube_pod_container_resource_limits{container="prometheus-operator",namespace="openshift-monitoring"}'`, token, `"pod":"prometheus-operator-`, 3*uwmLoadTime)
		result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment/prometheus-operator", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"prometheus-operator\")].resources.requests}", "-n", "openshift-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get prometheus-operator container resources.requests setting")
		o.Expect(result).To(o.ContainSubstring(`"cpu":"10m","memory":"200Mi"`))

		result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment/prometheus-operator", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"prometheus-operator\")].resources.limits}", "-n", "openshift-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get prometheus-operator container resources.limits setting")
		o.Expect(result).To(o.ContainSubstring(`"cpu":"20m","memory":"300Mi"`))

		exutil.By("check the resources.requests and resources.limits take effect for prometheus-operator-admission-webhook")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=kube_pod_container_resource_limits{container="prometheus-operator-admission-webhook",namespace="openshift-monitoring"}'`, token, `"pod":"prometheus-operator-admission-webhook-`, 3*uwmLoadTime)
		result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment/prometheus-operator-admission-webhook", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"prometheus-operator-admission-webhook\")].resources.requests}", "-n", "openshift-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get prometheus-operator-admission-webhook container resources.requests setting")
		o.Expect(result).To(o.ContainSubstring(`"cpu":"10m","memory":"50Mi"`))

		result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment/prometheus-operator-admission-webhook", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"prometheus-operator-admission-webhook\")].resources.limits}", "-n", "openshift-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get prometheus-operator-admission-webhook container resources.limits setting")
		o.Expect(result).To(o.ContainSubstring(`"cpu":"20m","memory":"100Mi"`))

		exutil.By("check the resources.requests and resources.limits take effect for telemeter-client")
		telemeterPod, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-l", "app.kubernetes.io/name=telemeter-client", "-n", "openshift-monitoring").Output()
		if strings.Contains(telemeterPod, "telemeter-client") {
			checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=kube_pod_container_resource_limits{container="telemeter-client",namespace="openshift-monitoring"}'`, token, `"pod":"telemeter-client-`, 3*uwmLoadTime)
			result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment/telemeter-client", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"telemeter-client\")].resources.requests}", "-n", "openshift-monitoring").Output()
			o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get telemeter-client container resources.requests setting")
			o.Expect(result).To(o.ContainSubstring(`"cpu":"2m","memory":"50Mi"`))

			result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment/telemeter-client", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"telemeter-client\")].resources.limits}", "-n", "openshift-monitoring").Output()
			o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get telemeter-client container resources.limits setting")
			o.Expect(result).To(o.ContainSubstring(`"cpu":"10m","memory":"100Mi"`))
		}

		createResourceFromYaml(oc, "openshift-user-workload-monitoring", uwmResources)
		exutil.AssertAllPodsToBeReady(oc, "openshift-user-workload-monitoring")

		exutil.By("check the resources.requests and resources.limits for uwm prometheus-operator")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=kube_pod_container_resource_limits{container="prometheus-operator",namespace="openshift-user-workload-monitoring"}'`, token, `"pod":"prometheus-operator-`, 3*uwmLoadTime)
		result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment/prometheus-operator", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"prometheus-operator\")].resources.requests}", "-n", "openshift-user-workload-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get UWM prometheus-operator container resources.requests setting")
		o.Expect(result).To(o.ContainSubstring(`"cpu":"2m","memory":"20Mi"`))
		result, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment/prometheus-operator", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"prometheus-operator\")].resources.limits}", "-n", "openshift-user-workload-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to get UWM prometheus-operator container resources.limits setting")
		o.Expect(result).To(o.ContainSubstring(`"cpu":"10m","memory":"100Mi"`))
	})

	// The test is already covered in pkg/manifests/manifests_test.go::TestNodeExporterCollectorSettings
	//author: tagao@redhat.com
	/* 	g.It("Author:tagao-High-67503-check On/Off switch of processes Collector in Node Exporter [Serial]", func() {
		var (
			enableProcesses = filepath.Join(monitoringBaseDir, "enableProcesses.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check processes Collector is disabled by default")
		exutil.AssertAllPodsToBeReady(oc, "openshift-monitoring")
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--no-collector.processes"))

		exutil.By("check processes metrics in prometheus k8s pod, should not have related metrics")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="processes"}'`, token, `"result":[]`, uwmLoadTime)

		exutil.By("enable processes in CMO config")
		createResourceFromYaml(oc, "openshift-monitoring", enableProcesses)

		exutil.By("check processes metrics in prometheus k8s pod again")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_scrape_collector_success{collector="processes"}'`, token, `"collector":"processes"`, 3*uwmLoadTime)
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_processes_max_processes'`, token, `"__name__":"node_processes_max_processes"`, 3*uwmLoadTime)
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_processes_pids'`, token, `"__name__":"node_processes_pids"`, 3*uwmLoadTime)
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_processes_state'`, token, `"__name__":"node_processes_state"`, 3*uwmLoadTime)
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_processes_threads'`, token, `"__name__":"node_processes_threads"`, 3*uwmLoadTime)
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=node_processes_threads_state'`, token, `"__name__":"node_processes_threads_state"`, 3*uwmLoadTime)

		exutil.By("check processes in daemonset")
		output, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("daemonset.apps/node-exporter", "-ojsonpath={.spec.template.spec.containers[?(@.name==\"node-exporter\")].args}", "-n", "openshift-monitoring").Output()
		o.Expect(output).To(o.ContainSubstring("--collector.processes"))
	}) */

	// The test is already covered in pkg/manifests/manifests_test.go::TestPrometheusRemoteWriteProxy
	// author: tagao@redhat.com
	/* 	g.It("Author:tagao-Medium-73009-CMO is correctly forwarding current proxy config to the prometheus operator in remote write configs [Serial]", func() {
		var (
			remotewriteCM = filepath.Join(monitoringBaseDir, "example-remotewrite-cm.yaml")
		)
		exutil.By("check cluster proxy")
		checkProxy, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("proxy", "cluster", "-ojsonpath={.spec}").Output()
		if checkProxy == "{}" || !strings.Contains(checkProxy, `http`) {
			g.Skip("This case should execute on a proxy cluster!")
		}

		exutil.By("delete uwm-config/cm-config at the end of a serial case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("Create example remotewrite cm under openshift-monitoring")
		createResourceFromYaml(oc, "openshift-monitoring", remotewriteCM)

		exutil.By("get http and https proxy URL")
		httpProxy, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("proxy", "cluster", "-ojsonpath={.spec.httpProxy}").Output()
		httpsProxy, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("proxy", "cluster", "-ojsonpath={.spec.httpsProxy}").Output()
		e2e.Logf("httpProxy:\n%s", httpProxy)
		e2e.Logf("httpsProxy:\n%s", httpsProxy)

		exutil.By("check prometheus remoteWrite configs applied")
		cmd := "-ojsonpath={.spec.remoteWrite[]}"
		checkValue := `"url":"https://test.remotewrite.com/api/write"`
		checkYamlconfig(oc, "openshift-monitoring", "prometheuses", "k8s", cmd, checkValue, true)
		proxyUrl, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("prometheuses", "k8s", "-ojsonpath={.spec.remoteWrite[].proxyUrl}", "-n", "openshift-monitoring").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("proxyUrl:\n%s", proxyUrl)

		exutil.By("check remoteWrite proxyUrl should be same as cluster proxy")
		if strings.Contains(proxyUrl, httpsProxy) {
			o.Expect(proxyUrl).NotTo(o.Equal(""))
			o.Expect(proxyUrl).To(o.Equal(httpsProxy))
		}
		if !strings.Contains(proxyUrl, httpsProxy) {
			o.Expect(proxyUrl).NotTo(o.Equal(""))
			o.Expect(proxyUrl).To(o.Equal(httpProxy))
		}
	}) */

	// author: tagao@redhat.com
	g.It("Author:tagao-Medium-73834-trigger PrometheusOperatorRejectedResources alert [Serial]", func() {
		var (
			PrometheusOperatorRejectedResources = filepath.Join(monitoringBaseDir, "PrometheusOperatorRejectedResources.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of the case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check the alert exist")
		cmd := "-ojsonpath={.spec.groups[].rules[?(@.alert==\"PrometheusOperatorRejectedResources\")]}"
		checkYamlconfig(oc, "openshift-monitoring", "prometheusrules", "prometheus-operator-rules", cmd, "PrometheusOperatorRejectedResources", true)

		exutil.By("trigger PrometheusOperatorRejectedResources alert")
		oc.SetupProject()
		ns := oc.Namespace()
		createResourceFromYaml(oc, ns, PrometheusOperatorRejectedResources)

		exutil.By("check alert metrics")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="PrometheusOperatorRejectedResources"}'`, token, `PrometheusOperatorRejectedResources`, 3*uwmLoadTime)
	})

	// author: tagao@redhat.com
	g.It("Author:tagao-Medium-73805-trigger PrometheusRuleFailures alert [Serial]", func() {
		var (
			PrometheusRuleFailures = filepath.Join(monitoringBaseDir, "PrometheusRuleFailures.yaml")
		)
		exutil.By("delete uwm-config/cm-config and test alert at the end of the case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("PrometheusRule", "example-alert", "-n", "openshift-monitoring", "--ignore-not-found").Execute()

		exutil.By("check the alert exist")
		cmd := "-ojsonpath={.spec.groups[].rules[?(@.alert==\"PrometheusRuleFailures\")]}"
		checkYamlconfig(oc, "openshift-monitoring", "prometheusrules", "prometheus-k8s-prometheus-rules", cmd, "PrometheusRuleFailures", true)

		exutil.By("trigger PrometheusRuleFailures alert")
		createResourceFromYaml(oc, "openshift-monitoring", PrometheusRuleFailures)

		exutil.By("check alert metrics")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=sum(irate(container_network_receive_bytes_total{pod!=""}[5m])) BY (pod, interface) + on(pod, interface) group_left(network_name) pod_network_name_info'`, token, `"error":"found duplicate series for the match group`, uwmLoadTime)
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="PrometheusRuleFailures"}'`, token, `PrometheusRuleFailures`, 3*uwmLoadTime)
	})

	// author: tagao@redhat.com
	g.It("Author:tagao-Medium-73804-trigger TargetDown alert [Serial]", func() {
		var (
			exampleApp = filepath.Join(monitoringBaseDir, "example-app.yaml")
		)
		exutil.By("delete uwm-config/cm-config and example-app at the end of the case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("deployment/prometheus-example-app", "service/prometheus-example-app", "servicemonitor/prometheus-example-monitor", "-n", "openshift-monitoring", "--ignore-not-found").Execute()

		exutil.By("check the alert exist")
		cmd := "-ojsonpath={.spec.groups[].rules[?(@.alert==\"TargetDown\")]}"
		checkYamlconfig(oc, "openshift-monitoring", "prometheusrules", "cluster-monitoring-operator-prometheus-rules", cmd, "TargetDown", true)

		exutil.By("trigger TargetDown alert")
		createResourceFromYaml(oc, "openshift-monitoring", exampleApp)
		//% oc patch ServiceMonitor/prometheus-example-monitor -n openshift-monitoring --type json -p '[{"op": "add", "path": "/spec/endpoints/0/scheme", "value": "https"}]'
		patchConfig := `[{"op": "add", "path": "/spec/endpoints/0/scheme", "value":"https"}]`
		patchErr := oc.AsAdmin().WithoutNamespace().Run("patch").Args("servicemonitor", "prometheus-example-monitor", "-p", patchConfig, "--type=json", "-n", "openshift-monitoring").Execute()
		o.Expect(patchErr).NotTo(o.HaveOccurred())

		exutil.By("check alert metrics")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="TargetDown",job="prometheus-example-app"}'`, token, `"alertname":"TargetDown"`, 3*uwmLoadTime)
	})

	// author: tagao@redhat.com
	g.It("Author:tagao-Medium-74734-Alert for broken Prometheus Kube Service Discovery", func() {
		var (
			exampleApp = filepath.Join(monitoringBaseDir, "example-app.yaml")
		)
		exutil.By("confirm the alert existed")
		// % oc -n openshift-monitoring get prometheusrules prometheus-k8s-prometheus-rules -ojsonpath='{.spec.groups[].rules[?(@.alert=="PrometheusKubernetesListWatchFailures")]}' |jq
		cmd := "-ojsonpath={.spec.groups[].rules[?(@.alert==\"PrometheusKubernetesListWatchFailures\")]}"
		checkYamlconfig(oc, "openshift-monitoring", "prometheusrules", "prometheus-k8s-prometheus-rules", cmd, `"alert":"PrometheusKubernetesListWatchFailures"`, true)

		exutil.By("create a namespace and deploy example-app")
		oc.SetupProject()
		ns := oc.Namespace()
		createResourceFromYaml(oc, ns, exampleApp)

		exutil.By("add label to the namespace")
		defer oc.AsAdmin().WithoutNamespace().Run("label").Args("namespace", ns, "openshift.io/cluster-monitoring-").Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("label").Args("namespace", ns, "openshift.io/cluster-monitoring=true").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		label, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("namespace", ns, `-ojsonpath={.metadata.labels}`).Output()
		e2e.Logf("test namespace labels: \n%v", label)
		o.Expect(label).To(o.ContainSubstring(`openshift.io/cluster-monitoring":"true`))

		exutil.By("confirm prometheus pod is ready")
		assertPodToBeReady(oc, "prometheus-k8s-0", "openshift-monitoring")

		exutil.By("confirm thanos-query pod is ready")
		//% oc get pod -n openshift-monitoring -l app.kubernetes.io/name=thanos-query
		waitErr := oc.AsAdmin().WithoutNamespace().Run("wait").Args("pod", "-l", "app.kubernetes.io/name=thanos-query", "-n", "openshift-monitoring", "--for=condition=Ready", "--timeout=3m").Execute()
		o.Expect(waitErr).NotTo(o.HaveOccurred())

		// debug log
		MONpod, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", "openshift-monitoring").Output()
		e2e.Logf("the MON pods condition: %s", MONpod)

		exutil.By("check the alert is triggered")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="PrometheusKubernetesListWatchFailures"}'`, token, `"alertname":"PrometheusKubernetesListWatchFailures"`, 3*uwmLoadTime)

		exutil.By("check logs in prometheus pod")
		checkLogWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/name=prometheus", "prometheus", `cannot list resource \"pods\" in API group \"\" in the namespace \"`+ns+`\"`, true)
	})

	// author: tagao@redhat.com
	g.It("Author:tagao-Medium-74311-trigger PrometheusRemoteWriteBehind alert [Serial]", func() {
		var (
			PrometheusRemoteWriteBehind = filepath.Join(monitoringBaseDir, "PrometheusRemoteWriteBehind.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of the case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("create fake remoteWrite")
		createResourceFromYaml(oc, "openshift-monitoring", PrometheusRemoteWriteBehind)

		exutil.By("check the alert exist")
		cmd := "-ojsonpath={.spec.groups[].rules[?(@.alert==\"PrometheusRemoteWriteBehind\")]}"
		checkYamlconfig(oc, "openshift-monitoring", "prometheusrules", "prometheus-k8s-prometheus-rules", cmd, "PrometheusRemoteWriteBehind", true)

		exutil.By("check logs in pod")
		checkLogWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/name=prometheus", "prometheus", "no such host", true)

		exutil.By("Get token of SA prometheus-k8s")
		token := getSAToken(oc, "prometheus-k8s", "openshift-monitoring")

		exutil.By("check alert triggered")
		checkMetric(oc, `https://thanos-querier.openshift-monitoring.svc:9091/api/v1/query --data-urlencode 'query=ALERTS{alertname="PrometheusRemoteWriteBehind"}'`, token, `"alertname":"PrometheusRemoteWriteBehind"`, 2*uwmLoadTime)
	})

	// author: tagao@redhat.com
	g.It("Author:tagao-Medium-76282-monitoring-plugin should reload cert/key files dynamically [Serial]", func() {
		exutil.By("delete uwm-config/cm-config at the end of the case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check openshift-monitoring/monitoring-plugin-cert secret exist")
		//% oc -n openshift-monitoring get secret monitoring-plugin-cert -ojsonpath='{.data}'
		cmd := "-ojsonpath={.data}"
		checkYamlconfig(oc, "openshift-monitoring", "secret", "monitoring-plugin-cert", cmd, `tls.crt`, true)
		checkYamlconfig(oc, "openshift-monitoring", "secret", "monitoring-plugin-cert", cmd, `tls.key`, true)
		secretBefore, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", "monitoring-plugin-cert", "-ojsonpath={.data}", "-n", "openshift-monitoring").Output()

		exutil.By("delete openshift-monitoring/monitoring-plugin-cert secret")
		err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("secret", "monitoring-plugin-cert", "-n", "openshift-monitoring").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("check the secret re-created")
		checkYamlconfig(oc, "openshift-monitoring", "secret", "monitoring-plugin-cert", cmd, `tls.crt`, true)
		checkYamlconfig(oc, "openshift-monitoring", "secret", "monitoring-plugin-cert", cmd, `tls.key`, true)
		secretAfter, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", "monitoring-plugin-cert", "-ojsonpath={.data}", "-n", "openshift-monitoring").Output()

		exutil.By("check the secret have a new hash")
		if strings.Compare(secretBefore, secretAfter) == 0 {
			e2e.Failf("secret not changed!")
		}
	})

	// The test is already covered in test/e2e/metrics_adapter_test.go::TestMetricsServerRollout
	// author: tagao@redhat.com
	/* 	g.It("Author:tagao-Medium-73291-Graduate MetricsServer FeatureGate to GA [Serial]", func() {
		var (
			metrics_server_test = filepath.Join(monitoringBaseDir, "metrics_server_test.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of the case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("label master node with metrics-server label")
		nodeList, err := getNodesWithLabel(oc, "node-role.kubernetes.io/master")
		o.Expect(err).NotTo(o.HaveOccurred())
		for _, node := range nodeList {
			defer oc.AsAdmin().WithoutNamespace().Run("label").Args("node", node, "metricsserver-").Execute()
			err = oc.AsAdmin().WithoutNamespace().Run("label").Args("node", node, "metricsserver=deploy").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		exutil.By("schedule metrics-server pods to master node")
		createResourceFromYaml(oc, "openshift-monitoring", metrics_server_test)
		podCheck := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 300*time.Second, true, func(context.Context) (bool, error) {
			output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", "openshift-monitoring", "-l", "app.kubernetes.io/component=metrics-server").Output()
			if err != nil || strings.Contains(output, "Terminating") {
				return true, nil
			}
			return false, nil
		})
		exutil.AssertWaitPollNoErr(podCheck, "metrics-server pods did not restarting!")

		exutil.By("confirm metrics-server pods scheduled to master nodes, this step may take few mins")
		waitForPodsToMatchReplicas(oc, "openshift-monitoring", "metrics-server", "app.kubernetes.io/component=metrics-server")
		podNames, err := getAllRunningPodsWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/component=metrics-server")
		o.Expect(err).NotTo(o.HaveOccurred())
		for _, pod := range podNames {
			nodeName, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", pod, "-ojsonpath={.spec.nodeName}", "-n", "openshift-monitoring").Output()
			nodeCheck, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName, "-ojsonpath={.metadata.labels}").Output()
			o.Expect(strings.Contains(string(nodeCheck), "node-role.kubernetes.io/master")).Should(o.BeTrue())
		}
		exutil.By("check config applied")
		for _, pod := range podNames {
			// % oc -n openshift-monitoring get pod metrics-server-7778dbf79b-8frpq -o jsonpath='{.spec.nodeSelector}' | jq
			cmd := "-ojsonpath={.spec.nodeSelector}"
			checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, `"metricsserver":"deploy"`, true)
			// % oc -n openshift-monitoring get pod metrics-server-7778dbf79b-8frpq -o jsonpath='{.spec.topologySpreadConstraints}' | jq
			cmd = "-ojsonpath={.spec.topologySpreadConstraints}"
			checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, `"app.kubernetes.io/name":"metrics-server"`, true)
			checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, `"maxSkew":2`, true)
			checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, `"topologyKey":"metricsserver"`, true)
			checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, `"whenUnsatisfiable":"DoNotSchedule"`, true)
			// % oc get pod -n openshift-monitoring metrics-server-c8cbfd6ff-pnk2z -o go-template='{{range.spec.containers}}{{"Container Name: "}}{{.name}}{{"\r\nresources: "}}{{.resources}}{{"\n"}}{{end}}'
			cmd = `-ogo-template={{range.spec.containers}}{{"Container Name: "}}{{.name}}{{"\r\nresources: "}}{{.resources}}{{"\n"}}{{end}}`
			checkYamlconfig(oc, "openshift-monitoring", "pod", pod, cmd, `resources: map[limits:map[cpu:50m memory:500Mi] requests:map[cpu:10m memory:50Mi]]`, true)
		}
	}) */

	// author: tagao@redhat.com
	g.It("Author:tagao-Medium-72776-Enable audit logging to Metrics Server - invalid value [Serial]", func() {
		var (
			invalid_value_audit_profile = filepath.Join(monitoringBaseDir, "invalid_value_audit_profile.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of the case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check default audit level is Metadata")
		//% oc -n openshift-monitoring get deploy metrics-server -ojsonpath='{.spec.template.spec.containers[?(@.name=="metrics-server")].args}' | jq
		cmd := `-ojsonpath={.spec.template.spec.containers[?(@.name=="metrics-server")].args}`
		checkYamlconfig(oc, "openshift-monitoring", "deploy", "metrics-server", cmd, `"--audit-policy-file=/etc/audit/metadata-profile.yaml"`, true)

		exutil.By("set invalid value for audit profile")
		createResourceFromYaml(oc, "openshift-monitoring", invalid_value_audit_profile)

		exutil.By("check failed log in CMO")
		checkLogWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/name=cluster-monitoring-operator", "cluster-monitoring-operator", `adapter audit profile: metadata`, true)
	})

	// author: tagao@redhat.com
	g.It("Author:tagao-Medium-72707-Enable audit logging to Metrics Server [Serial]", func() {
		var (
			valid_value_audit_profile = filepath.Join(monitoringBaseDir, "valid_value_audit_profile.yaml")
		)
		exutil.By("delete uwm-config/cm-config at the end of the case")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)

		exutil.By("check audit file path")
		//% oc -n openshift-monitoring get deploy metrics-server -ojsonpath='{.spec.template.spec.containers[?(@.name=="metrics-server")].args}' | jq
		cmd := `-ojsonpath={.spec.template.spec.containers[?(@.name=="metrics-server")].args}`
		checkYamlconfig(oc, "openshift-monitoring", "deploy", "metrics-server", cmd, `"--audit-policy-file=/etc/audit/metadata-profile.yaml"`, true)

		exutil.By("check the audit log")
		//% oc -n openshift-monitoring exec -c metrics-server metrics-server-777f5464ff-5fdvh -- cat /var/log/metrics-server/audit.log
		getReadyPodsWithLabels(oc, "openshift-monitoring", "app.kubernetes.io/component=metrics-server")
		podNames, err := getAllRunningPodsWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/component=metrics-server")
		o.Expect(err).NotTo(o.HaveOccurred())
		for _, pod := range podNames {
			cmd := "cat /var/log/metrics-server/audit.log"
			checkConfigInsidePod(oc, "openshift-monitoring", "metrics-server", pod, cmd, `"level":"Metadata"`, true)
		}

		exutil.By("set audit profile as Request")
		createResourceFromYaml(oc, "openshift-monitoring", valid_value_audit_profile)

		exutil.By("check the deploy config applied")
		//oc -n openshift-monitoring get deploy metrics-server -ojsonpath='{.spec.template.spec.containers[?(@.name=="metrics-server")].args}' | jq
		cmd = `-ojsonpath={.spec.template.spec.containers[?(@.name=="metrics-server")].args}`
		checkYamlconfig(oc, "openshift-monitoring", "deploy", "metrics-server", cmd, `"--audit-policy-file=/etc/audit/request-profile.yaml"`, true)

		exutil.By("check the policy reflect into pod")
		waitForPodsToMatchReplicas(oc, "openshift-monitoring", "metrics-server", "app.kubernetes.io/component=metrics-server")
		podNames, err = getAllRunningPodsWithLabel(oc, "openshift-monitoring", "app.kubernetes.io/component=metrics-server")
		o.Expect(err).NotTo(o.HaveOccurred())
		for _, pod := range podNames {
			//oc -n openshift-monitoring exec -c metrics-server metrics-server-85db9c79c8-sljdb -- cat /etc/audit/request-profile.yaml
			cmd := "cat /etc/audit/request-profile.yaml"
			checkConfigInsidePod(oc, "openshift-monitoring", "metrics-server", pod, cmd, `"name": "Request"`, true)
			checkConfigInsidePod(oc, "openshift-monitoring", "metrics-server", pod, cmd, `"level": "Request"`, true)
			//oc -n openshift-monitoring exec -c metrics-server metrics-server-85db9c79c8-sljdb -- cat /var/log/metrics-server/audit.log
			cmd = "cat /var/log/metrics-server/audit.log"
			checkConfigInsidePod(oc, "openshift-monitoring", "metrics-server", pod, cmd, `level":"Request"`, true)
		}
	})

	// author: hongyli@redhat.com
	g.It("Author:hongyli-Critical-44032-Restore cluster monitoring stack default configuration [Serial]", func() {
		defer deleteConfig(oc, monitoringCM.name, monitoringCM.namespace)
		exutil.By("Delete config map user-workload--monitoring-config")
		defer deleteConfig(oc, "user-workload-monitoring-config", "openshift-user-workload-monitoring")
		exutil.By("Delete config map cluster-monitoring-config")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("alertmanager", "test-alertmanager", "-n", "openshift-user-workload-monitoring", "--ignore-not-found").Execute()
		exutil.By("Delete alertmanager under openshift-user-workload-monitoring")
	})
})

// NOTE: Please do not add new tests here. The goal is to merge Ginkgo tests into the E2E suite to get a single, unified testing framework.
