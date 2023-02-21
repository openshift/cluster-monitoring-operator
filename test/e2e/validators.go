package e2e

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
)

type validator interface {
	Validate(obj runtime.Object) error
}

type genChange int64

func (g genChange) Validate(obj runtime.Object) error {
	objMeta, err := meta.Accessor(obj)
	if err != nil {
		return err
	}
	if objMeta.GetGeneration() == int64(g) {
		ns, name := objMeta.GetNamespace(), objMeta.GetName()
		return fmt.Errorf("%s/%s: no new generation was found after %d", ns, name, g)
	}
	return nil
}
