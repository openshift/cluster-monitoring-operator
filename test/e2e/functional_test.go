package prometheus

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo"
	o "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"
	kapierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	watchtools "k8s.io/client-go/tools/watch"
	"k8s.io/kubernetes/pkg/client/conditions"
	e2e "k8s.io/kubernetes/test/e2e/framework"

	exutil "github.com/openshift/origin/test/extended/util"
)

const waitForPrometheusStartSeconds = 240

var _ = g.Describe("[Feature:Prometheus][Conformance] Prometheus", func() {
	defer g.GinkgoRecover()
	var (
		oc = exutil.NewCLIWithoutNamespace("prometheus")

		url, bearerToken string
	)

	g.BeforeEach(func() {
		var ok bool
		url, bearerToken, ok = locatePrometheus(oc)
		if !ok {
			e2e.Skipf("Prometheus could not be located on this cluster, skipping prometheus test")
		}
	})

	g.Describe("when run on the cluster", func() {

		oc = exutil.NewCLI("monitoring", exutil.KubeConfigPath())

		g.It("prometheus & alertmanager pods should use anti-affinity", func() {
			oc.SetNamespace("openshift-monitoring")
			e2e.Logf("Add admin role to current user.")
			err := oc.AsAdmin().Run("adm").Args("policy", "add-role-to-user", "admin", oc.Username()).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())

			e2e.Logf("Get list of pods for specific namespace.")
			podList, err := oc.AdminKubeClient().CoreV1().Pods(oc.Namespace()).List(metav1.ListOptions{})

			if err != nil {
				e2e.Logf("Error in podList: %v", err)
				return
			}

			var alm = `affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - podAffinityTerm:
          labelSelector:
            matchExpressions:
            - key: alertmanager
              operator: In
              values:
              - main`

			var k8s = `affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - podAffinityTerm:
          labelSelector:
            matchExpressions:
            - key: prometheus
              operator: In
              values:
              - k8s`

			for _, pod := range podList.Items {
				if strings.Contains(pod.Name, "alertmanager-main") {
					e2e.Logf("Try to get %s pod config.", pod.Name)
					podYamlOutput, err := oc.Run("get").Args("pod", pod.Name, "-o", "yaml").Output()
					if err != nil {
						e2e.Logf("Error with getting pod yaml: %s\n", err)
					}
					e2e.Logf("Check that pod config include proper ani-affinity section.")
					o.Expect(strings.Contains(strings.TrimSpace(podYamlOutput), strings.TrimSpace(alm))).To(o.Equal(true))
				}

				if strings.Contains(pod.Name, "prometheus-k8s") {
					e2e.Logf("Try to get %s pod config.", pod.Name)
					podYamlOutput, err := oc.Run("get").Args("pod", pod.Name, "-o", "yaml").Output()
					if err != nil {
						e2e.Logf("Error with getting pod yaml: %s\n", err)
					}
					e2e.Logf("Check that pod config include proper ani-affinity section.")
					o.Expect(strings.Contains(strings.TrimSpace(podYamlOutput), strings.TrimSpace(k8s))).To(o.Equal(true))
				}
			}

		})

		g.It("terminationMessagePolicy for cluster-monitoring-operator pod should be: FallbackToLogsOnError", func() {
			oc.SetNamespace("openshift-monitoring")
			e2e.Logf("Add admin role to current user.")
			err := oc.AsAdmin().Run("adm").Args("policy", "add-role-to-user", "admin", oc.Username()).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())

			e2e.Logf("Get list of pods for specific namespace.")
			podList, err := oc.AdminKubeClient().CoreV1().Pods(oc.Namespace()).List(metav1.ListOptions{})

			if err != nil {
				e2e.Logf("Error in podList: %v", err)
				return
			}

			terminationMessage := `terminationMessagePolicy: FallbackToLogsOnError`

			for _, pod := range podList.Items {
				if strings.Contains(pod.Name, "cluster-monitoring-operator") {
					e2e.Logf("Try to get %s pod config.", pod.Name)
					podYamlOutput, err := oc.Run("get").Args("pod", pod.Name, "-o", "yaml").Output()
					if err != nil {
						e2e.Logf("Error with getting pod yaml: %s\n", err)
					}
					e2e.Logf("Check that pod config include proper terminationMessagePolicy section.")
					o.Expect(strings.Contains(strings.TrimSpace(podYamlOutput), strings.TrimSpace(terminationMessage))).To(o.Equal(true))
				}

			}

		})

		g.It("and ClusterOperator named monitoring is populated", func() {
			oc.SetNamespace("openshift-monitoring")
			e2e.Logf("Add cluster admin role to current user.")
			err := oc.AsAdmin().Run("adm").Args("policy", "add-cluster-role-to-user", "cluster-admin", oc.Username()).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())

			clusterOperatorText := `kind: ClusterOperator`
			nameText := `name: monitoring`

			e2e.Logf("Try to get cluster operator configuration.")
			clusterOperatorCfgOutput, err := oc.Run("get").Args("ClusterOperator", "monitoring", "-o", "yaml").Output()
			if err != nil {
				e2e.Logf("Error with getting cluster operator yaml: %s\n", err)
			}
			e2e.Logf("Check that cluster operator configuration includes proper name section.")
			o.Expect(strings.Contains(strings.TrimSpace(clusterOperatorCfgOutput), strings.TrimSpace(clusterOperatorText))).To(o.Equal(true))
			o.Expect(strings.Contains(strings.TrimSpace(clusterOperatorCfgOutput), strings.TrimSpace(nameText))).To(o.Equal(true))

			routeAlertManager := "alertmanager-main"
			routeGrafana := "grafana"
			routePometheusK8s := "prometheus-k8s"
			routes := map[int]string{1: routeAlertManager, 2: routeGrafana, 3: routePometheusK8s}

			e2e.Logf("Will get all possible routes in 'openshift-monitoring' name space.")
			routeOutput, err := oc.Run("get").Args("route", "--no-headers").Output()
			if err != nil {
				e2e.Logf("Error with getting routes: %s\n", err)
			}

			for _, v := range routes {
				e2e.Logf("Check existing basic route -- %s", v)
				o.Expect(strings.Contains(strings.TrimSpace(routeOutput), v)).To(o.Equal(true))
			}

		})

		g.It("Use prometheus adapter to serve resource metrics API", func() {
			oc.SetNamespace("openshift-monitoring")
			e2e.Logf("Add cluster admin role to current user.")
			err := oc.AsAdmin().Run("adm").Args("policy", "add-cluster-role-to-user", "cluster-admin", oc.Username()).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())

			cmd := [...]string{"pod prometheus-adapter",
				"ClusterRole prometheus-adapter",
				"ClusterRole resource-metrics-server-resources",
				"ClusterRoleBinding prometheus-adapter",
				"ClusterRoleBinding resource-metrics:system:auth-delegator",
				"ServiceAccount prometheus-adapter",
				"ConfigMap adapter-config",
				"Deployment prometheus-adapter",
				"svc prometheus-adapter",
				"APIService v1beta1.metrics.k8s.io",
				"ServiceAccount prometheus-adapter"}

			var pureDigitTime []string
			var hour int64
			var min int64

			var checkTime = func(time []string, variant int) bool {

				var result bool = false
				var strBuf strings.Builder

				for _, line := range time {
					if strBuf.Len() == 0 {
						strBuf.WriteString(line)
						strBuf.WriteString(" ")

					} else {
						strBuf.WriteString(line)
					}
				}

				strTime := strings.Split(strBuf.String(), " ")

				switch variant {
				case 1: // 6h19m

					hour, _ = strconv.ParseInt(strTime[0], 10, 0)
					min, _ = strconv.ParseInt(strTime[1], 10, 0)
					if hour > 0 || min > 0 {
						result = true
					}
				case 2: // 6h
					hour, _ = strconv.ParseInt(strTime[0], 10, 0)
					if hour > 0 {
						result = true
					}
				case 3: // 19m
					min, _ = strconv.ParseInt(strTime[0], 10, 0)
					if min > 0 {
						result = true
					}
				}
				return result

			}

			var parseTime = func(hm string) bool {
				if strings.Contains(hm, "h") && strings.Contains(hm, "m") {
					pureIntTime = nil
					hm1 := strings.Split(hm, "h")
					pureIntTime = append(pureIntTime, hm1[0])
					hm2 := strings.Split(hm1[1], "m")
					pureIntTime = append(pureIntTime, hm2[0])
					return checkTime(pureIntTime, 1)
				}

				if strings.Contains(hm, "h") {
					pureIntTime = nil
					hm1 := strings.Split(hm, "h")
					pureIntTime = append(pureIntTime, hm1[0])
					return checkTime(pureIntTime, 2)
				}

				if strings.Contains(hm, "m") {
					pureIntTime = nil
					hm1 := strings.Split(hm, "m")
					pureIntTime = append(pureIntTime, hm1[0])
					return checkTime(pureIntTime, 3)
				} else {
					fmt.Println("Something wrong with cluster.")
				}
				return false
			}

			for _, args := range cmd {
				_args := strings.Split(args, " ")
				e2e.Logf("Check that %s exist for 'get %s output", _args[0], _args[1])
				cmdOutput, err := oc.Run("get").Args(_args[0], "--no-headers").Output()
				o.Expect(err).NotTo(o.HaveOccurred())
				if err != nil {
					e2e.Logf("Error with getting info about %s, %s\n", _args[0], err)
					g.Fail("Fail, can not get important service information.")
				}
				splittedCmdOutput := strings.Split(cmdOutput, "\n")

				for _, line := range splittedCmdOutput {
					if strings.Contains(line, _args[1]) {
						fmt.Println(line)
						splittedLine := strings.Split(line, " ")
						runTime := splittedLine[len(splittedLine)-1]
						e2e.Logf("Check that %s service runtime %s is more 0", _args[1], runTime)
						o.Expect(parseTime(runTime)).To(o.Equal(true))

					} else {
						e2e.Logf("Error, can not find line: %s\n", _args[1], err)
						g.Fail("Fail, can't find parameter.")

					}
				}
			}

		})

	})
})

func expectURLStatusCodeExec(ns, execPodName, url string, statusCode int) error {
	cmd := fmt.Sprintf("curl -k -s -o /dev/null -w '%%{http_code}' %q", url)
	output, err := e2e.RunHostCmd(ns, execPodName, cmd)
	if err != nil {
		return fmt.Errorf("host command failed: %v\n%s", err, output)
	}
	if output != strconv.Itoa(statusCode) {
		return fmt.Errorf("last response from server was not %d: %s", statusCode, output)
	}
	return nil
}

func expectBearerTokenURLStatusCodeExec(ns, execPodName, url, bearer string, statusCode int) error {
	cmd := fmt.Sprintf("curl -k -s -H 'Authorization: Bearer %s' -o /dev/null -w '%%{http_code}' %q", bearer, url)
	output, err := e2e.RunHostCmd(ns, execPodName, cmd)
	if err != nil {
		return fmt.Errorf("host command failed: %v\n%s", err, output)
	}
	if output != strconv.Itoa(statusCode) {
		return fmt.Errorf("last response from server was not %d: %s", statusCode, output)
	}
	return nil
}

func getBearerTokenURLViaPod(ns, execPodName, url, bearer string) (string, error) {
	cmd := fmt.Sprintf("curl -s -k -H 'Authorization: Bearer %s' %q", bearer, url)
	output, err := e2e.RunHostCmd(ns, execPodName, cmd)
	if err != nil {
		return "", fmt.Errorf("host command failed: %v\n%s", err, output)
	}
	return output, nil
}

func waitForServiceAccountInNamespace(c clientset.Interface, ns, serviceAccountName string, timeout time.Duration) error {
	w, err := c.CoreV1().ServiceAccounts(ns).Watch(metav1.SingleObject(metav1.ObjectMeta{Name: serviceAccountName}))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err = watchtools.UntilWithoutRetry(ctx, w, conditions.ServiceAccountHasSecrets)
	return err
}

func locatePrometheus(oc *exutil.CLI) (url, bearerToken string, ok bool) {
	_, err := oc.AdminKubeClient().CoreV1().Services("openshift-monitoring").Get("prometheus-k8s", metav1.GetOptions{})
	if kapierrs.IsNotFound(err) {
		return "", "", false
	}

	waitForServiceAccountInNamespace(oc.AdminKubeClient(), "openshift-monitoring", "prometheus-k8s", 2*time.Minute)
	for i := 0; i < 30; i++ {
		secrets, err := oc.AdminKubeClient().CoreV1().Secrets("openshift-monitoring").List(metav1.ListOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
		for _, secret := range secrets.Items {
			if secret.Type != v1.SecretTypeServiceAccountToken {
				continue
			}
			if !strings.HasPrefix(secret.Name, "prometheus-") {
				continue
			}
			bearerToken = string(secret.Data[v1.ServiceAccountTokenKey])
			break
		}
		if len(bearerToken) == 0 {
			e2e.Logf("Waiting for prometheus service account secret to show up")
			time.Sleep(time.Second)
			continue
		}
	}
	o.Expect(bearerToken).ToNot(o.BeEmpty())

	return "https://prometheus-k8s.openshift-monitoring.svc:9091", bearerToken, true
}
