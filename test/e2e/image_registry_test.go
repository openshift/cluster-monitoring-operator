package e2e

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestImageRegistryPods ensure that all the containers images in the Platform monitoring
// ns are from the same registry than the CMO's image
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
	// Get all pods
	pods := f.MustListPods(t, ns, "")
	require.Greater(t, len(pods.Items), 1)

	// Get CMO registry
	var cmoRegistry string
	for _, pod := range cmoPod.Items {
		containers := pod.Spec.Containers
		require.Len(t, containers, 1, "the check assumes only one container is present")
		cmoRegistry = getRegistry(t, containers[0].Image)
		break
	}
	require.NotEmpty(t, cmoRegistry)

	// Check equality with the others'
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			require.Equal(t, cmoRegistry, getRegistry(t, container.Image))
		}

	}
}
