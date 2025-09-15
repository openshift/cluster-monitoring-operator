// Derived from code originally published in
//
//	https://github.com/openshift/openshift-tests-private
//
// at commit a6a189840b006da18c8203950983c0cee5ea7354.
package util

// GetResourceSpecificLabelValue gets the specified label value from the resource and label name
func GetResourceSpecificLabelValue(oc *CLI, resourceKindAndName string, resourceNamespace string, labelName string) (string, error) {
	var cargs []string
	if resourceNamespace != "" {
		cargs = append(cargs, "-n", resourceNamespace)
	}
	cargs = append(cargs, resourceKindAndName, "-o=jsonpath={.metadata.labels."+labelName+"}")
	return oc.AsAdmin().WithoutNamespace().Run("get").Args(cargs...).Output()
}

// AddLabelsToSpecificResource adds the custom labels to the specific resource
func AddLabelsToSpecificResource(oc *CLI, resourceKindAndName string, resourceNamespace string, labels ...string) (string, error) {
	var cargs []string
	if resourceNamespace != "" {
		cargs = append(cargs, "-n", resourceNamespace)
	}
	cargs = append(cargs, resourceKindAndName)
	cargs = append(cargs, labels...)
	cargs = append(cargs, "--overwrite")
	return oc.AsAdmin().WithoutNamespace().Run("label").Args(cargs...).Output()
}

// DeleteLabelsFromSpecificResource deletes the custom labels from the specific resource
func DeleteLabelsFromSpecificResource(oc *CLI, resourceKindAndName string, resourceNamespace string, labelNames ...string) (string, error) {
	var cargs []string
	if resourceNamespace != "" {
		cargs = append(cargs, "-n", resourceNamespace)
	}
	cargs = append(cargs, resourceKindAndName)
	cargs = append(cargs, StringsSliceElementsAddSuffix(labelNames, "-")...)
	return oc.AsAdmin().WithoutNamespace().Run("label").Args(cargs...).Output()
}

// StringsSliceElementsAddSuffix returns a new string slice all elements with the specific suffix added
func StringsSliceElementsAddSuffix(stringsSlice []string, suffix string) []string {
	if len(stringsSlice) == 0 {
		return []string{}
	}
	var newStringsSlice = make([]string, 0, 10)
	for _, element := range stringsSlice {
		newStringsSlice = append(newStringsSlice, element+suffix)
	}
	return newStringsSlice
}
