// Derived from code originally published in
//
//	https://github.com/openshift/openshift-tests-private
//
// at commit a6a189840b006da18c8203950983c0cee5ea7354.
package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os/exec"
	"strconv"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	exutil "github.com/openshift/cluster-monitoring-operator/test/monitoring/util"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

const platformLoadTime = 120
const uwmLoadTime = 180

type monitoringConfig struct {
	name               string
	namespace          string
	enableUserWorkload bool
	template           string
}

func (cm *monitoringConfig) create(oc *exutil.CLI) {
	if !checkConfigMap(oc, "openshift-monitoring", "cluster-monitoring-config") {
		e2e.Logf("Create configmap: cluster-monitoring-config")
		output, err := applyResourceFromTemplate(oc, "--ignore-unknown-parameters=true", "-f", cm.template, "-p", "NAME="+cm.name, "NAMESPACE="+cm.namespace, "ENABLEUSERWORKLOAD="+fmt.Sprintf("%v", cm.enableUserWorkload))
		if err != nil {
			if strings.Contains(output, "AlreadyExists") {
				err = nil
			}
		}
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

func createUWMConfig(oc *exutil.CLI, uwmMonitoringConfig string) {
	if !checkConfigMap(oc, "openshift-user-workload-monitoring", "user-workload-monitoring-config") {
		e2e.Logf("Create configmap: user-workload-monitoring-config")
		output, err := oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", uwmMonitoringConfig).Output()
		if err != nil {
			if strings.Contains(output, "AlreadyExists") {
				err = nil
			}
		}
		o.Expect(err).NotTo(o.HaveOccurred())
	}
}

// check if a configmap is created in specific namespace [usage: checkConfigMap(oc, namespace, configmapName)]
func checkConfigMap(oc *exutil.CLI, ns, configmapName string) bool {
	searchOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("cm", configmapName, "-n", ns, "-o=jsonpath={.data.config\\.yaml}").Output()
	if err != nil {
		return false
	}
	if strings.Contains(searchOutput, "retention") {
		return true
	}
	return false
}

func getRandomString() string {
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	seed := rand.New(rand.NewSource(time.Now().UnixNano()))
	buffer := make([]byte, 8)
	for index := range buffer {
		buffer[index] = chars[seed.Intn(len(chars))]
	}
	return string(buffer)
}

// the method is to create one resource with template
func applyResourceFromTemplate(oc *exutil.CLI, parameters ...string) (string, error) {
	var configFile string
	err := wait.PollUntilContextTimeout(context.TODO(), 3*time.Second, 15*time.Second, false, func(context.Context) (bool, error) {

		output, err := oc.AsAdmin().Run("process").Args(parameters...).OutputToFile(getRandomString() + "cluster-monitoring.json")
		if err != nil {
			return false, nil
		}
		configFile = output
		return true, nil
	})
	exutil.AssertWaitPollNoErr(err, fmt.Sprintf("fail to process %v", parameters))
	return oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", configFile).Output()
}

func labelNameSpace(oc *exutil.CLI, namespace string, label string) {
	err := oc.AsAdmin().WithoutNamespace().Run("label").Args("namespace", namespace, label, "--overwrite").Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("The namespace %s is labeled by %q", namespace, label)

}

func getSAToken(oc *exutil.CLI, account, ns string) string {
	e2e.Logf("Getting a token assigned to specific serviceaccount from %s namespace...", ns)
	token, err := oc.AsAdmin().WithoutNamespace().Run("create").Args("token", account, "-n", ns).Output()
	if err != nil {
		if strings.Contains(token, "unknown command") {
			token, err = oc.AsAdmin().WithoutNamespace().Run("sa").Args("get-token", account, "-n", ns).Output()
		}
	}
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(token).NotTo(o.BeEmpty())
	return token
}

// check data by running curl on a pod
func checkMetric(oc *exutil.CLI, url, token, metricString string, timeout time.Duration) {
	var metrics string
	var err error
	getCmd := "curl -G -k -s -H \"Authorization:Bearer " + token + "\" " + url
	err = wait.PollUntilContextTimeout(context.TODO(), 3*time.Second, timeout*time.Second, false, func(context.Context) (bool, error) {
		metrics, err = exutil.RemoteShPod(oc, "openshift-monitoring", "prometheus-k8s-0", "sh", "-c", getCmd)
		if err != nil || !strings.Contains(metrics, metricString) {
			return false, nil
		}
		return true, err
	})
	exutil.AssertWaitPollNoErr(err, fmt.Sprintf("The metrics %s failed to contain %s", metrics, metricString))
}

func createResourceFromYaml(oc *exutil.CLI, ns, yamlFile string) {
	err := oc.AsAdmin().Run("apply").Args("-n", ns, "-f", yamlFile).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func deleteBindMonitoringViewRoleToDefaultSA(oc *exutil.CLI, uwmFederateRBACViewName string) {
	err := oc.AdminKubeClient().RbacV1().ClusterRoleBindings().Delete(context.Background(), uwmFederateRBACViewName, metav1.DeleteOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
}

func bindMonitoringViewRoleToDefaultSA(oc *exutil.CLI, ns, uwmFederateRBACViewName string) (*rbacv1.ClusterRoleBinding, error) {
	return oc.AdminKubeClient().RbacV1().ClusterRoleBindings().Create(context.Background(), &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: uwmFederateRBACViewName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "cluster-monitoring-view",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "default",
				Namespace: ns,
			},
		},
	}, metav1.CreateOptions{})
}
func deleteClusterRoleBinding(oc *exutil.CLI, clusterRoleBindingName string) {
	err := oc.AdminKubeClient().RbacV1().ClusterRoleBindings().Delete(context.Background(), clusterRoleBindingName, metav1.DeleteOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
}
func bindClusterRoleToUser(oc *exutil.CLI, clusterRoleName, userName, clusterRoleBindingName string) (*rbacv1.ClusterRoleBinding, error) {
	return oc.AdminKubeClient().RbacV1().ClusterRoleBindings().Create(context.Background(), &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     clusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "User",
				Name: userName,
			},
		},
	}, metav1.CreateOptions{})
}

func checkRoute(oc *exutil.CLI, ns, name, token, queryString, metricString string, timeout time.Duration) {
	var metrics string
	err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, timeout*time.Second, false, func(context.Context) (bool, error) {
		path, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("route", name, "-n", ns, "-o=jsonpath={.spec.path}").Output()
		if err != nil {
			return false, nil
		}
		host, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("route", name, "-n", ns, "-o=jsonpath={.spec.host}").Output()
		if err != nil {
			return false, nil
		}
		metricCMD := fmt.Sprintf("curl -G -s -k -H \"Authorization: Bearer %s\" https://%s%s --data-urlencode '%s'", token, host, path, queryString)
		curlOutput, err := exec.Command("bash", "-c", metricCMD).Output()
		if err != nil {
			return false, nil
		}
		metrics = string(curlOutput)
		if !strings.Contains(metrics, metricString) {
			return false, nil
		}
		return true, err
	})
	exutil.AssertWaitPollNoErr(err, fmt.Sprintf("The metrics %s failed to contain %s", metrics, metricString))
}

// check thanos_ruler retention
func checkRetention(oc *exutil.CLI, ns string, sts string, expectedRetention string, timeout time.Duration) {
	err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, timeout*time.Second, false, func(context.Context) (bool, error) {
		stsObject, err := oc.AdminKubeClient().AppsV1().StatefulSets(ns).Get(context.Background(), sts, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		args := stsObject.Spec.Template.Spec.Containers[0].Args
		for _, v := range args {
			if strings.Contains(v, expectedRetention) {
				return true, nil
			}
		}
		return false, nil
	})
	exutil.AssertWaitPollNoErr(err, fmt.Sprintf("the retention of %s is not expected %s", sts, expectedRetention))
}

func deleteConfig(oc *exutil.CLI, configName, ns string) {
	err := oc.AsAdmin().WithoutNamespace().Run("delete").Args("ConfigMap", configName, "-n", ns, "--ignore-not-found").Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

// patch&check enforcedBodySizeLimit value in cluster-monitoring-config
func patchAndCheckBodySizeLimit(oc *exutil.CLI, limitValue string, checkValue string) {
	data := map[string]map[string]string{
		"data": {
			"config.yaml": fmt.Sprintf("prometheusK8s:\n  enforcedBodySizeLimit: \"%s\"", limitValue),
		},
	}
	jsonBytes, _ := json.Marshal(data)
	patchLimit := oc.AsAdmin().WithoutNamespace().Run("patch").Args("cm", "cluster-monitoring-config", "-p", string(jsonBytes), "--type=merge", "-n", "openshift-monitoring").Execute()
	o.Expect(patchLimit).NotTo(o.HaveOccurred())
	e2e.Logf("enforcedBodySizeLimit value: %v", limitValue)

	checkLimit := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 360*time.Second, false, func(context.Context) (bool, error) {
		limit, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-monitoring", "-c", "prometheus", "prometheus-k8s-0", "--", "bash", "-c", "cat /etc/prometheus/config_out/prometheus.env.yaml | grep body_size_limit | uniq").Output()
		if err != nil || !strings.Contains(limit, checkValue) {
			return false, nil
		}
		return true, nil
	})
	exutil.AssertWaitPollNoErr(checkLimit, "failed to check limit")
}

// check remote write config in the pod
func checkRmtWrtConfig(oc *exutil.CLI, ns string, podName string, checkValue string) {
	envCheck := wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 360*time.Second, false, func(context.Context) (bool, error) {
		envOutput, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", ns, "-c", "prometheus", podName, "--", "bash", "-c", fmt.Sprintf(`cat "/etc/prometheus/config_out/prometheus.env.yaml" | grep '%s'`, checkValue)).Output()
		if err != nil || !strings.Contains(envOutput, checkValue) {
			return false, nil
		}
		return true, nil
	})
	exutil.AssertWaitPollNoErr(envCheck, "failed to check remote write config")
}

// check Alerts or Metrics are not exist, Metrics is more recommended to use util `checkMetric`
func checkAlertNotExist(oc *exutil.CLI, url, token, alertName string, timeout time.Duration) {
	cmd := "curl -G -k -s -H \"Authorization:Bearer " + token + "\" " + url
	err := wait.PollUntilContextTimeout(context.TODO(), 3*time.Second, timeout*time.Second, false, func(context.Context) (bool, error) {
		chk, err := exutil.RemoteShPod(oc, "openshift-monitoring", "prometheus-k8s-0", "sh", "-c", cmd)
		o.Expect(err).NotTo(o.HaveOccurred())
		if err != nil || strings.Contains(chk, alertName) {
			return false, nil
		}
		return true, err
	})
	exutil.AssertWaitPollNoErr(err, fmt.Sprintf("Target alert found: %s", alertName))
}

// check alertmanager config in the pod
func checkAlertmanagerConfig(oc *exutil.CLI, ns string, podName string, checkValue string, expectExist bool) {
	envCheck := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 180*time.Second, false, func(context.Context) (bool, error) {
		envOutput, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", ns, "-c", "alertmanager", podName, "--", "bash", "-c", fmt.Sprintf(`cat /etc/alertmanager/config_out/alertmanager.env.yaml | grep '%s'`, checkValue)).Output()
		if expectExist {
			if err != nil || !strings.Contains(envOutput, checkValue) {
				return false, nil
			}
			return true, nil
		}
		if !expectExist {
			if !strings.Contains(envOutput, checkValue) {
				return true, nil
			}
			return false, nil
		}
		return false, nil
	})
	exutil.AssertWaitPollNoErr(envCheck, "failed to check alertmanager config")
}

// check prometheus config in the pod
func checkPrometheusConfig(oc *exutil.CLI, ns string, podName string, checkValue string, expectExist bool) {
	envCheck := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 300*time.Second, false, func(context.Context) (bool, error) {
		envOutput, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", ns, "-c", "prometheus", podName, "--", "bash", "-c", fmt.Sprintf(`cat /etc/prometheus/config_out/prometheus.env.yaml | grep '%s'`, checkValue)).Output()
		if expectExist {
			if err != nil || !strings.Contains(envOutput, checkValue) {
				return false, nil
			}
			return true, nil
		}
		if !expectExist {
			if err != nil || !strings.Contains(envOutput, checkValue) {
				return true, nil
			}
			return false, nil
		}
		return false, nil
	})
	exutil.AssertWaitPollNoErr(envCheck, "failed to check prometheus config")
}

// check configuration in the pod in the given time for specific container
func checkConfigInPod(oc *exutil.CLI, namespace string, podName string, containerName string, cmd string, checkValue string) {
	podCheck := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 240*time.Second, false, func(context.Context) (bool, error) {
		Output, err := exutil.RemoteShPodWithBashSpecifyContainer(oc, namespace, podName, containerName, cmd)
		if err != nil || !strings.Contains(Output, checkValue) {
			return false, nil
		}
		return true, nil
	})
	exutil.AssertWaitPollNoErr(podCheck, "failed to check configuration in the pod")
}

// check specific pod logs in container
func checkLogsInContainer(oc *exutil.CLI, namespace string, podName string, containerName string, checkValue string) {
	err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 240*time.Second, false, func(context.Context) (bool, error) {
		Output, err := oc.AsAdmin().WithoutNamespace().Run("logs").Args("-n", namespace, podName, "-c", containerName).Output()
		if err != nil || !strings.Contains(Output, checkValue) {
			return false, nil
		}
		return true, nil
	})
	exutil.AssertWaitPollNoErr(err, fmt.Sprintf("failed to find \"%s\" in the pod logs", checkValue))
}

// get specific pod name with label then describe pod info
func getSpecPodInfo(oc *exutil.CLI, ns string, label string, checkValue string) {
	envCheck := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 180*time.Second, false, func(context.Context) (bool, error) {
		podName, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", ns, "-l", label, "-ojsonpath={.items[].metadata.name}").Output()
		output, err := oc.AsAdmin().WithoutNamespace().Run("describe").Args("pod", podName, "-n", ns).Output()
		if err != nil || !strings.Contains(output, checkValue) {
			return false, nil
		}
		return true, nil
	})
	exutil.AssertWaitPollNoErr(envCheck, fmt.Sprintf("failed to find \"%s\" in the pod yaml", checkValue))
}

// check pods with label that are fully deleted
func checkPodDeleted(oc *exutil.CLI, ns string, label string, checkValue string) {
	podCheck := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 240*time.Second, false, func(context.Context) (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", ns, "-l", label).Output()
		if err != nil || strings.Contains(output, checkValue) {
			return false, nil
		}
		return true, nil
	})
	exutil.AssertWaitPollNoErr(podCheck, fmt.Sprintf("found \"%s\" exist or not fully deleted", checkValue))
}

// query monitoring metrics, alerts from a specific pod
func queryFromPod(oc *exutil.CLI, url, token, ns, pod, container, metricString string, timeout time.Duration) {
	var metrics string
	var err error
	getCmd := "curl -G -k -s -H \"Authorization:Bearer " + token + "\" " + url
	err = wait.PollUntilContextTimeout(context.TODO(), 3*time.Second, timeout*time.Second, false, func(context.Context) (bool, error) {
		metrics, err = oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", ns, "-c", container, pod, "--", "bash", "-c", getCmd).Output()
		if err != nil || !strings.Contains(metrics, metricString) {
			return false, nil
		}
		return true, err
	})
	exutil.AssertWaitPollNoErr(err, fmt.Sprintf("The metrics %s failed to contain %s", metrics, metricString))
}

// check config exist or absent in yaml/json
func checkYamlconfig(oc *exutil.CLI, ns string, components string, componentsName string, cmd string, checkValue string, expectExist bool) {
	configCheck := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 240*time.Second, false, func(context.Context) (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(components, componentsName, cmd, "-n", ns).Output()
		if expectExist {
			if err != nil || !strings.Contains(output, checkValue) {
				e2e.Logf("output: \n%v", output)
				return false, nil
			}
			return true, nil
		}
		if !expectExist {
			if err != nil || !strings.Contains(output, checkValue) {
				return true, nil
			}
			return false, nil
		}
		e2e.Logf("output: \n%v", output)
		return false, nil
	})
	exutil.AssertWaitPollNoErr(configCheck, fmt.Sprintf("base on `expectExist=%v`, did (not) find \"%s\" exist", expectExist, checkValue))
}

// check logs through label
func checkLogWithLabel(oc *exutil.CLI, namespace string, label string, containerName string, checkValue string, expectExist bool) {
	err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 240*time.Second, false, func(context.Context) (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("logs").Args("-n", namespace, "-l", label, "-c", containerName, "--tail=-1").Output()
		if expectExist {
			if err != nil || !strings.Contains(output, checkValue) {
				return false, nil
			}
			return true, nil
		}
		if !expectExist {
			if err != nil || !strings.Contains(output, checkValue) {
				return true, nil
			}
			return false, nil
		}
		return false, nil
	})
	exutil.AssertWaitPollNoErr(err, fmt.Sprintf("failed to find \"%s\" in the pod logs", checkValue))
}

// assertPodToBeReady poll pod status to determine it is ready, skip check when pods do not exist.
func assertPodToBeReady(oc *exutil.CLI, podName string, namespace string) {
	err := wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 3*time.Minute, false, func(context.Context) (bool, error) {
		stdout, err := oc.AsAdmin().Run("get").Args("pod", podName, "-n", namespace, "--ignore-not-found", "-o", "jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}'").Output()
		if err != nil {
			e2e.Logf("the err:%v, and try next round", err)
			return false, nil
		}
		if strings.Contains(stdout, "True") {
			e2e.Logf("Pod %s is ready!", podName)
			return true, nil
		}
		if stdout == "" {
			e2e.Logf("ignore check, Pod %s is not found", podName)
			return true, nil
		}
		return false, nil
	})
	exutil.AssertWaitPollNoErr(err, fmt.Sprintf("Pod %s status is not ready!", podName))
}

// use exec command to check configs/files inside the pod
func checkConfigInsidePod(oc *exutil.CLI, ns string, container string, pod string, cmd string, checkValue string, expectExist bool) {
	configCheck := wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 360*time.Second, false, func(context.Context) (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", ns, "-c", container, pod, "--", "bash", "-c", cmd).Output()
		if expectExist {
			if err != nil || !strings.Contains(output, checkValue) {
				return false, nil
			}
			return true, nil
		}
		if !expectExist {
			if err != nil || !strings.Contains(output, checkValue) {
				return true, nil
			}
			return false, nil
		}
		return false, nil
	})
	exutil.AssertWaitPollNoErr(configCheck, fmt.Sprintf("base on `expectExist=%v`, did (not) find \"%s\" exist", expectExist, checkValue))
}

// ensures the pod remains in Ready state for a specific duration
func ensurePodRemainsReady(oc *exutil.CLI, podName string, namespace string, timeout time.Duration, interval time.Duration) {
	endTime := time.Now().Add(timeout)

	for time.Now().Before(endTime) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", podName, "-n", namespace, "-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status}`).Output()
		if err != nil || !strings.Contains(output, "True") {
			e2e.Logf("Pod %s is not Ready, current status: %s, err: %v\n", podName, output, err)
		} else {
			e2e.Logf("Pod %s is Running and Ready\n", podName)
		}
		time.Sleep(interval)
	}
	//Final confirmation of pod condition
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", podName, "-n", namespace, "-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status}`).Output()
	if err != nil || !strings.Contains(output, "True") {
		e2e.Logf("Pod %s is not Ready, current status: %s, err: %v\n", podName, output, err)
	} else {
		e2e.Logf("Pod %s is Running and Ready\n", podName)
	}
}

// getAllRunningPodsWithLabel get array of all running pods for a given namespace and label
func getAllRunningPodsWithLabel(oc *exutil.CLI, namespace string, label string) ([]string, error) {
	pods, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", namespace, "-l", label, "--field-selector=status.phase=Running").Template("{{range .items}}{{.metadata.name}}{{\" \"}}{{end}}").Output()
	if len(pods) == 0 {
		return []string{}, err
	}
	e2e.Logf("pods: \n%v", pods)
	return strings.Split(pods, " "), err
}

// alertmanagerTestPodCheck poll check on alertmanager-test-alertmanager-0 pod until ready
func alertmanagerTestPodCheck(oc *exutil.CLI) {
	err := wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 180*time.Second, false, func(context.Context) (bool, error) {
		podStats, err := oc.AsAdmin().Run("get").Args("pod", "alertmanager-test-alertmanager-0", "-n", "openshift-user-workload-monitoring").Output()
		if err != nil || strings.Contains(podStats, "not found") {
			return false, nil
		}
		if err != nil || strings.Contains(podStats, "Init:0/1") {
			return false, nil
		}
		if err != nil || strings.Contains(podStats, "ContainerCreating") {
			return false, nil
		}
		e2e.Logf("pod is ready: \n%v", podStats)
		return true, nil
	})
	exutil.AssertWaitPollNoErr(err, "pod not created")
}

// getReadyPodsWithLabels poll check pod through a given label until pod is ready
func getReadyPodsWithLabels(oc *exutil.CLI, ns string, label string) {
	podCheck := wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 10*time.Minute, true, func(context.Context) (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", ns, "-l", label, "-o", "jsonpath={.items[*].status.phase}").Output()
		if err != nil {
			return false, nil
		}
		podList := strings.Fields(output)
		if len(podList) == 0 {
			return false, nil
		}
		for _, status := range strings.Fields(output) {
			if status != "Running" {
				return false, nil
			}
		}
		return true, nil
	})

	if podCheck != nil {
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", ns, "-l", label).Output()
		e2e.Logf("pods not ready: \n%v", output)
	}

	exutil.AssertWaitPollNoErr(podCheck, "some pods are not ready!")
}

// getNodesWithLabel get array of all node for a given label
func getNodesWithLabel(oc *exutil.CLI, label string) ([]string, error) {
	nodes, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", "-l", label, "-ojsonpath={.items[*].metadata.name}").Output()
	if len(nodes) == 0 {
		e2e.Logf("target node names: \n%v", nodes)
		return []string{}, err
	}
	return strings.Split(nodes, " "), err
}

// isSNOEnvironment confirm whether this env is single node cluster
func isSNOEnvironment(oc *exutil.CLI) (bool, error) {
	nodes, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "-o=jsonpath={.items[*].metadata.name}").Output()
	if err != nil {
		return false, err
	}

	nodeList := strings.Split(nodes, " ")

	if len(nodeList) <= 1 {
		e2e.Logf("Detected SNO environment with %d node(s)", len(nodeList))
		return true, nil
	}

	e2e.Logf("Detected multi-node environment with %d nodes", len(nodeList))
	return false, nil
}

// checkPodDisruptionBudgetIfNotSNO check pdb if its not sno env
func checkPodDisruptionBudgetIfNotSNO(oc *exutil.CLI) {
	isSNO, err := isSNOEnvironment(oc)
	o.Expect(err).NotTo(o.HaveOccurred())

	if isSNO {
		exutil.By("Skipping PodDisruptionBudget check in SNO environment")
		return
	}

	exutil.By("Waiting for PodDisruptionBudget to be available in multi-node environment")

	err = wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 120*time.Second, false, func(context.Context) (bool, error) {
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("PodDisruptionBudget", "monitoring-plugin", "-n", "openshift-monitoring").Output()
		if err != nil {
			return false, nil
		}
		if !strings.Contains(output, "not found") {
			return true, nil
		}
		return false, nil
	})

	o.Expect(err).NotTo(o.HaveOccurred(), "PodDisruptionBudget monitoring-plugin was not found within the timeout period")

	exutil.By("Checking PodDisruptionBudget after it is ready")
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("PodDisruptionBudget", "monitoring-plugin", "-n", "openshift-monitoring").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(output).NotTo(o.ContainSubstring("not found"))
}

func getDeploymentReplicas(oc *exutil.CLI, ns string, deployName string) (int, error) {
	var expectedReplicas, readyReplicas, updatedReplicas int

	// Wait for deployment to be available
	waitErr := oc.AsAdmin().WithoutNamespace().Run("wait").Args("deployment/"+deployName, "-n", ns, "--for=condition=Available", "--timeout=120s").Execute()
	o.Expect(waitErr).NotTo(o.HaveOccurred())

	// Poll until all replicas match
	err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 1*time.Minute, true, func(ctx context.Context) (bool, error) {
		// Get spec.replicas
		specReplicas, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment", deployName, "-n", ns, "-o", "jsonpath={.spec.replicas}").Output()
		if err != nil {
			e2e.Logf("Failed to get spec.replicas for deployment %s: %v", deployName, err)
			return false, nil
		}
		expectedReplicas, err = strconv.Atoi(specReplicas)
		if err != nil {
			e2e.Logf("Failed to parse spec.replicas for deployment %s: %v", deployName, err)
			return false, nil
		}

		// Get status.readyReplicas
		readyReplicasStr, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment", deployName, "-n", ns, "-o", "jsonpath={.status.readyReplicas}").Output()
		if err != nil {
			e2e.Logf("Failed to get readyReplicas for deployment %s: %v", deployName, err)
			return false, nil
		}
		readyReplicas, _ = strconv.Atoi(readyReplicasStr)

		// Get status.updatedReplicas
		updatedReplicasStr, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment", deployName, "-n", ns, "-o", "jsonpath={.status.updatedReplicas}").Output()
		if err != nil {
			e2e.Logf("Failed to get updatedReplicas for deployment %s: %v", deployName, err)
			return false, nil
		}
		updatedReplicas, _ = strconv.Atoi(updatedReplicasStr)

		// Ensure all replicas match
		if expectedReplicas == readyReplicas && expectedReplicas == updatedReplicas {
			return true, nil
		}

		e2e.Logf("Waiting for deployment %s to have matching replicas: spec=%d, ready=%d, updated=%d", deployName, expectedReplicas, readyReplicas, updatedReplicas)
		return false, nil
	})

	if err != nil {
		return 0, fmt.Errorf("failed to get matching replicas for deployment %s: %v", deployName, err)
	}
	e2e.Logf("Deployment %s has matching replicas: %d", deployName, expectedReplicas)
	return expectedReplicas, nil
}

// waitForPodsToMatchReplicas Poll to check if the number of running Pods matches the number of replicas expected by the Deployment
func waitForPodsToMatchReplicas(oc *exutil.CLI, namespace string, deployName string, label string) {
	err := wait.PollUntilContextTimeout(context.TODO(), 10*time.Second, 10*time.Minute, true, func(ctx context.Context) (bool, error) {
		expectedReplicas, err := getDeploymentReplicas(oc, namespace, deployName)
		if err != nil {
			e2e.Logf("Error getting expected replicas: %v", err)
			return false, nil
		}

		runningPods, err := getAllRunningPodsWithLabel(oc, namespace, label)
		if err != nil {
			e2e.Logf("Error getting running pods: %v", err)
			return false, nil
		}

		if len(runningPods) != expectedReplicas {
			e2e.Logf("Mismatch: expected %d running pods, but found %d", expectedReplicas, len(runningPods))
			return false, nil
		}

		e2e.Logf("Pods match expected replicas: %d/%d", len(runningPods), expectedReplicas)
		return true, nil
	})

	exutil.AssertWaitPollNoErr(err, "Pods did not reach the expected number!")
}
