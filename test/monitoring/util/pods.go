// Derived from code originally published in
//
//	https://github.com/openshift/openshift-tests-private
//
// at commit a6a189840b006da18c8203950983c0cee5ea7354.
package util

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kutilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/pod"
)

// WaitForNoPodsAvailable waits until there are no pods in the
// given namespace
func WaitForNoPodsAvailable(oc *CLI) error {
	return wait.Poll(200*time.Millisecond, 3*time.Minute, func() (bool, error) {
		pods, err := oc.KubeClient().CoreV1().Pods(oc.Namespace()).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		return len(pods.Items) == 0, nil
	})
}

// RemovePodsWithPrefixes deletes pods whose name begins with the
// supplied prefixes
func RemovePodsWithPrefixes(oc *CLI, prefixes ...string) error {
	e2e.Logf("Removing pods from namespace %s with prefix(es): %v", oc.Namespace(), prefixes)
	pods, err := oc.AdminKubeClient().CoreV1().Pods(oc.Namespace()).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	errs := []error{}
	for _, prefix := range prefixes {
		for _, pod := range pods.Items {
			if strings.HasPrefix(pod.Name, prefix) {
				if err := oc.AdminKubeClient().CoreV1().Pods(oc.Namespace()).Delete(context.Background(), pod.Name, metav1.DeleteOptions{}); err != nil {
					e2e.Logf("unable to remove pod %s/%s", oc.Namespace(), pod.Name)
					errs = append(errs, err)
				}
			}
		}
	}
	if len(errs) > 0 {
		return kutilerrors.NewAggregate(errs)
	}
	return nil
}

// CreateCentosExecPodOrFail creates a centos:7 pause pod used as a vessel for kubectl exec commands.
// Pod name is uniquely generated.
func CreateCentosExecPodOrFail(client kubernetes.Interface, ns, generateName string, tweak func(*v1.Pod)) *v1.Pod {
	return pod.CreateExecPodOrFail(context.TODO(), client, ns, generateName, func(pod *v1.Pod) {
		pod.Spec.Containers[0].Image = "centos:7"
		pod.Spec.Containers[0].Command = []string{"sh", "-c", "trap exit TERM; while true; do sleep 5; done"}
		pod.Spec.Containers[0].Args = nil

		if tweak != nil {
			tweak(pod)
		}
	})
}

// If no container is provided (empty string "") it will default to the first container
func remoteShPod(oc *CLI, namespace string, podName string, needBash bool, needChroot bool, container string, cmd ...string) (string, error) {
	var cargs []string
	var containerArgs []string
	if needBash {
		cargs = []string{"-n", namespace, podName, "bash", "-c"}
	} else if needChroot {
		cargs = []string{"-n", namespace, podName, "chroot", "/rootfs"}
	} else {
		cargs = []string{"-n", namespace, podName}
	}

	if container != "" {
		containerArgs = []string{"-c", container}
	} else {
		containerArgs = []string{}
	}

	allArgs := append(containerArgs, cargs...)
	allArgs = append(allArgs, cmd...)
	return oc.AsAdmin().WithoutNamespace().Run("rsh").Args(allArgs...).Output()
}

// RemoteShPod creates a remote shell of the pod
func RemoteShPod(oc *CLI, namespace string, podName string, cmd ...string) (string, error) {
	return remoteShPod(oc, namespace, podName, false, false, "", cmd...)
}

// RemoteShPodWithBashSpecifyContainer creates a remote shell of the pod with bash specifying container name
func RemoteShPodWithBashSpecifyContainer(oc *CLI, namespace string, podName string, containerName string, cmd ...string) (string, error) {
	return remoteShPod(oc, namespace, podName, true, false, containerName, cmd...)
}

// WaitAndGetSpecificPodLogs wait and return the pod logs by the specific filter
func WaitAndGetSpecificPodLogs(oc *CLI, namespace string, container string, podName string, filter string) (string, error) {
	logs, err := GetSpecificPodLogs(oc, namespace, container, podName, filter)
	if err != nil {
		waitErr := wait.Poll(20*time.Second, 10*time.Minute, func() (bool, error) {
			logs, err = GetSpecificPodLogs(oc, namespace, container, podName, filter)
			if err != nil {
				e2e.Logf("the err:%v, and try next round", err)
				return false, nil
			}
			if logs != "" {
				return true, nil
			}
			return false, nil
		})
		AssertWaitPollNoErr(waitErr, fmt.Sprintf("Pod logs does not contain %s", filter))
	}
	return logs, nil
}

// Pod Parameters can be used to set the template parameters except PodName as PodName can be provided using pod.Name
type Pod struct {
	Name       string
	Namespace  string
	Template   string
	Parameters []string
}

// AssertPodToBeReady poll pod status to determine it is ready
func AssertPodToBeReady(oc *CLI, podName string, namespace string) {
	err := wait.Poll(10*time.Second, 3*time.Minute, func() (bool, error) {
		stdout, err := oc.AsAdmin().Run("get").Args("pod", podName, "-n", namespace, "-o", "jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}'").Output()
		if err != nil {
			e2e.Logf("the err:%v, and try next round", err)
			return false, nil
		}
		if strings.Contains(stdout, "True") {
			e2e.Logf("Pod %s is ready!", podName)
			return true, nil
		}
		return false, nil
	})
	AssertWaitPollNoErr(err, fmt.Sprintf("Pod %s status is not ready!", podName))
}

// GetSpecificPodLogs returns the pod logs by the specific filter
func GetSpecificPodLogs(oc *CLI, namespace string, container string, podName string, filter string) (string, error) {
	return GetSpecificPodLogsCombinedOrNot(oc, namespace, container, podName, filter, false)
}

// GetSpecificPodLogsCombinedOrNot returns the pod logs by the specific filter with combining stderr or not
func GetSpecificPodLogsCombinedOrNot(oc *CLI, namespace string, container string, podName string, filter string, combined bool) (string, error) {
	var cargs []string
	if len(container) > 0 {
		cargs = []string{"-n", namespace, "-c", container, podName}
	} else {
		cargs = []string{"-n", namespace, podName}
	}
	podLogs, err := oc.AsAdmin().WithoutNamespace().Run("logs").Args(cargs...).OutputToFile("podLogs.txt")
	if err != nil {
		e2e.Logf("unable to get the pod (%s) logs", podName)
		return podLogs, err
	}
	var filterCmd = ""
	if len(filter) > 0 {
		filterCmd = " | grep -i " + filter
	}
	var filteredLogs []byte
	var errCmd error
	if combined {
		filteredLogs, errCmd = exec.Command("bash", "-c", "cat "+podLogs+filterCmd).CombinedOutput()
	} else {
		filteredLogs, errCmd = exec.Command("bash", "-c", "cat "+podLogs+filterCmd).Output()
	}
	return string(filteredLogs), errCmd
}

// GetAllPodsWithLabel get array of all pods for a given namespace and label
func GetAllPodsWithLabel(oc *CLI, namespace string, label string) ([]string, error) {
	pods, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pods", "-n", namespace, "-l", label).Template("{{range .items}}{{.metadata.name}}{{\" \"}}{{end}}").Output()
	if len(pods) == 0 {
		return []string{}, err
	}
	return strings.Split(pods, " "), err
}

// AssertAllPodsToBeReadyWithPollerParams assert all pods in NS are in ready state until timeout in a given namespace
// Pros: allow user to customize poller parameters
func AssertAllPodsToBeReadyWithPollerParams(oc *CLI, namespace string, interval, timeout time.Duration) {
	err := wait.Poll(interval, timeout, func() (bool, error) {

		// get the status flag for all pods
		// except the ones which are in Complete Status.
		// it use 'ne' operator which is only compatible with 4.10+ oc versions
		template := "'{{- range .items -}}{{- range .status.conditions -}}{{- if ne .reason \"PodCompleted\" -}}{{- if eq .type \"Ready\" -}}{{- .status}} {{\" \"}}{{- end -}}{{- end -}}{{- end -}}{{- end -}}'"
		stdout, err := oc.AsAdmin().Run("get").Args("pods", "-n", namespace).Template(template).Output()
		if err != nil {
			e2e.Logf("the err:%v, and try next round", err)
			return false, nil
		}
		if strings.Contains(stdout, "False") {
			return false, nil
		}
		return true, nil
	})
	AssertWaitPollNoErr(err, fmt.Sprintf("Some Pods are not ready in NS %s!", namespace))
}

// AssertAllPodsToBeReady assert all pods in NS are in ready state until timeout in a given namespace
func AssertAllPodsToBeReady(oc *CLI, namespace string) {
	AssertAllPodsToBeReadyWithPollerParams(oc, namespace, 10*time.Second, 4*time.Minute)
}
