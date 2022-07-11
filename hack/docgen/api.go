// Copyright 2022 The Cluster Monitoring Operator Authors
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

package main

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/openshift/cluster-monitoring-operator/hack/docgen/model"
)

const (
	firstParagraph = `
**NOTE**: The contents of this file are **automatically generated** from source code comments. 
If you wish to make a change or an addition to the content in this document, do so by **changing the code comments**.

# Cluster Monitoring Configuration Reference

Parts of Cluster Monitoring are configurable. Depending on which part of the stack users want to configure, they should edit the following:

- Configuration of OpenShift Container Platform monitoring components lies in a ConfigMap called ` + "`cluster-monitoring-config`" + ` in the ` + "`openshift-monitoring`" + ` namespace. Defined by [ClusterMonitoringConfiguration](#clustermonitoringconfiguration).
- Configuration of components that monitor user-defined projects lies in a ConfigMap called ` + "`user-workload-monitoring-config`" + ` in the ` + "`openshift-user-workload-monitoring`" + ` namespace. Defined by [UserWorkloadConfiguration](#userworkloadconfiguration).

The configuration file itself is always defined under the ` + "`config.yaml`" + ` key within the ConfigMap's data.

Monitoring a platform such as OpenShift requires a coordination of multiple components that must work well between themselves.
However, users should be able to customize the monitoring stack in such a way that they end up with a resilient and highly available monitoring solution.
Despite this, to avoid users from misconfiguring the monitoring stack of their clusters not all configuration parameters are exposed.

Configuring Cluster Monitoring is optional. If the config does not exist or is empty or malformed, then defaults will be used.`
)

func toSectionLink(name string) string {
	name = strings.ToLower(name)
	name = strings.Replace(name, " ", "-", -1)
	return name
}

func printAPIDocs(args []string) {
	fmt.Println(firstParagraph)

	// Build external documentation link with the
	// KubeAPI and PrometheusOperator versions
	model.BuildExternalDocLinks(args[0], args[1])

	paths := args[2:]
	typeSetUnion := make(model.TypeSet)
	typeSets := make([]model.TypeSet, 0, len(paths))
	for _, path := range paths {
		typeSet, err := model.Load(path)
		if err != nil {
			log.Fatal(err)
		}

		typeSets = append(typeSets, typeSet)
		for k, v := range typeSet {
			typeSetUnion[k] = v
		}
	}

	fmt.Printf("\n## Table of Contents\n")
	for _, typeSet := range typeSets {
		for _, key := range typeSet.SortedKeys() {
			t := typeSet[key]
			if len(t.Fields) == 0 {
				continue
			}

			fmt.Printf("* [%s](#%s)\n", t.Name, toSectionLink(t.Name))
		}
	}

	for _, typeSet := range typeSets {
		for _, key := range typeSet.SortedKeys() {
			t := typeSet[key]
			if len(t.Fields) == 0 {
				continue
			}

			fmt.Printf("\n## %s\n\n#### Description\n\n%s\n\n", t.Name, t.Description())

			printRequiredSection(t)

			backlinks := getBacklinks(t, typeSetUnion)
			if len(backlinks) > 0 {
				fmt.Printf("\n<em>appears in: %s</em>\n\n", strings.Join(backlinks, ", "))
			}

			fmt.Println("| Property | Type | Description |")
			fmt.Println("| -------- | ---- | ----------- |")
			for _, f := range t.Fields {
				if strings.HasPrefix(fmt.Sprint(f.Description()), "OmitFromDoc") {
					continue
				}
				fmt.Println("|", f.Name(), "|", f.TypeLink(typeSetUnion), "|", f.Description(), "|")
			}
			fmt.Println("")
			fmt.Println("[Back to TOC](#table-of-contents)")
		}
	}
}

func printRequiredSection(t *model.StructType) {
	hasRequiredFields := false
	for _, f := range t.Fields {
		if f.IsRequired() == true {
			hasRequiredFields = true
			break
		}
	}

	if hasRequiredFields {
		fmt.Println("#### Required")
		for _, f := range t.Fields {
			if f.IsRequired() == true {
				fmt.Println("   - `", f.Name(), "`")
			}
		}
	}
}

func getBacklinks(t *model.StructType, typeSet model.TypeSet) []string {
	appearsIn := make(map[string]struct{})
	for _, v := range typeSet {
		if v.IsOnlyEmbedded() {
			continue
		}

		for _, f := range v.Fields {
			if f.TypeName() == t.Name {
				appearsIn[v.Name] = struct{}{}
			}
		}
	}

	var backlinks []string
	for item := range appearsIn {
		link := fmt.Sprintf("[%s](#%s)", item, toSectionLink(item))
		backlinks = append(backlinks, link)
	}
	sort.Strings(backlinks)

	return backlinks
}
