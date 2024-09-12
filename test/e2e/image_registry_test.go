package e2e

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestImageRegistryPods ensure that all the containers images in openshift-monitoring
// are from the same registry than the CMO's image.
func TestImageRegistryPods(t *testing.T) {
	cmoImageRegistryIsUsedInNsAssert(t, f.Ns)
}

func cmoImageRegistryIsUsedInNsAssert(t *testing.T, ns string) func(t *testing.T) {
	return func(t *testing.T) {
		assertCMOImageRegistryIsUsed(t, ns)
	}
}

func assertCMOImageRegistryIsUsed(t *testing.T, ns string) {
	getRegistry := func(t *testing.T, image string) string {
		// This first attempt is needed; otherwise, we may blindly add a second scheme,
		// and the initial one will be considered the hostname.
		u, err := url.ParseRequestURI(image)
		if err == nil {
			return u.Host
		}
		// Maybe no scheme, add one.
		u, err = url.ParseRequestURI("stubheader://" + image)
		require.NoError(t, err)
		return u.Host
	}

	cmoPod := f.MustListPods(t, f.Ns, "app.kubernetes.io/name=cluster-monitoring-operator")
	require.Len(t, cmoPod.Items, 1)

	// Get CMO registry
	cmoContainers := cmoPod.Items[0].Spec.Containers
	require.Len(t, cmoContainers, 1, "the check assumes only one container is present")
	cmoRegistry := getRegistry(t, cmoContainers[0].Image)
	require.NotEmpty(t, cmoRegistry)

	// Get all pods
	pods := f.MustListPods(t, ns, "")
	require.GreaterOrEqual(t, len(pods.Items), 2)

	// Check equality with the others'
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			require.Equal(t, cmoRegistry, getRegistry(t, container.Image))
		}

	}
}
