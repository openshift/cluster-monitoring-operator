// Copyright 2021 The Cluster Monitoring Operator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// ------------------------------------------------------------------------- //
// The drain package is a partial copy of "k8s.io/kubectl/pkg/drain" which   //
// allows cordoning and annotating nodes atomically. This allow marking the  //
// nodes cordoned by an operator to avoid temptering someone else cordon.    //
// Since this is not supported by the original package, we preferred copying //
// part of the package and extending it to fit our needs.                    //
// ------------------------------------------------------------------------- //
package drain

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubectl/pkg/drain"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/client-go/kubernetes"
)

const (
	Cordon                  = true
	Uncordon                = false
	cordonAnnotationMessage = "node marked as unschedulable by an operator to reschedule a pod on another node"
)

// Helper wraps drain.Helper to annotate the nodes that will be drained by the
// operator
type Helper struct {
	drain.Helper
	annotation string
}

// NewHelper returns a new Helper
func NewHelper(ctx context.Context, client kubernetes.Interface, annotation string) *Helper {
	return &Helper{
		drain.Helper{
			Ctx:    ctx,
			Client: client,
		},
		annotation,
	}
}

// CordonHelper wraps functionality to cordon/uncordon nodes
type CordonHelper struct {
	node       *corev1.Node
	desired    bool
	annotation string
}

// NewCordonHelper returns a new CordonHelper
func NewCordonHelper(node *corev1.Node, annotation string) *CordonHelper {
	return &CordonHelper{
		node:       node,
		annotation: annotation,
	}
}

// UpdateIfRequired returns true if c.node.Spec.Unschedulable isn't already set,
// or false when no change is needed
// It also has a condition to prevent unschedulable nodes that aren't marked by
// the operator to be updated. This prevent tempering someone else cordon.
func (c *CordonHelper) UpdateIfRequired(desired bool) bool {
	c.desired = desired

	// Do not update unschedulable nodes that aren't annotated to not temper with
	// a cordon not owned by the operator
	_, annotated := c.node.Annotations[c.annotation]
	if !annotated && !desired {
		return false
	}

	return c.node.Spec.Unschedulable != c.desired
}

// PatchOrReplaceWithContext provides the option to pass a custom context while updating
// the node status
func (c *CordonHelper) PatchOrReplaceWithContext(clientCtx context.Context, clientset kubernetes.Interface, serverDryRun bool) (error, error) {
	client := clientset.CoreV1().Nodes()

	oldData, err := json.Marshal(c.node)
	if err != nil {
		return err, nil
	}

	c.node.Spec.Unschedulable = c.desired
	if c.node.Spec.Unschedulable {
		if c.node.Annotations != nil {
			c.node.Annotations[c.annotation] = cordonAnnotationMessage
		} else {
			c.node.Annotations = map[string]string{c.annotation: cordonAnnotationMessage}
		}
	} else {
		delete(c.node.Annotations, c.annotation)
	}

	newData, err := json.Marshal(c.node)
	if err != nil {
		return err, nil
	}

	patchBytes, patchErr := strategicpatch.CreateTwoWayMergePatch(oldData, newData, c.node)
	if patchErr == nil {
		patchOptions := metav1.PatchOptions{}
		if serverDryRun {
			patchOptions.DryRun = []string{metav1.DryRunAll}
		}
		_, err = client.Patch(clientCtx, c.node.Name, types.StrategicMergePatchType, patchBytes, patchOptions)
	} else {
		updateOptions := metav1.UpdateOptions{}
		if serverDryRun {
			updateOptions.DryRun = []string{metav1.DryRunAll}
		}
		_, err = client.Update(clientCtx, c.node, updateOptions)
	}
	return err, patchErr
}

// RunCordonOrUncordon demonstrates the canonical way to cordon or uncordon a Node
func RunCordonOrUncordon(drainer *Helper, node *corev1.Node, desired bool) error {
	c := NewCordonHelper(node, drainer.annotation)

	if updateRequired := c.UpdateIfRequired(desired); !updateRequired {
		// Already done
		return nil
	}

	err, patchErr := c.PatchOrReplaceWithContext(drainer.Ctx, drainer.Client, false)
	if err != nil {
		if patchErr != nil {
			return fmt.Errorf("cordon error: %s; merge patch error: %s", err.Error(), patchErr.Error())
		}
		return fmt.Errorf("cordon error: %s", err.Error())
	}

	return nil
}
