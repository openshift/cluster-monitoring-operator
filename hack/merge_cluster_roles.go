// Copyright 2020 The Cluster Monitoring Operator Authors
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
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ghodss/yaml"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ClusterRole struct {
	rbacv1.ClusterRole `yaml:",inline"`
	rules              map[string]rbacv1.PolicyRule
}

func NewClusterRole(manifest []byte) *ClusterRole {
	var (
		meta metav1.TypeMeta
		cr   ClusterRole
	)

	err := yaml.Unmarshal(manifest, &meta)
	if err != nil {
		log.Fatal(err)
	}

	switch kind := meta.Kind; {
	case strings.HasSuffix(kind, "RoleList"):
		var crList rbacv1.ClusterRoleList
		err = yaml.Unmarshal(manifest, &crList)
		if err != nil {
			log.Fatal(err)
		}
		for _, role := range crList.Items {
			cr.merge(&ClusterRole{ClusterRole: role})
		}
	case strings.HasSuffix(kind, "Role"):
		if kind != "ClusterRole" {
			log.Printf("creating a ClusterRole from a %s", kind)
		}
		err = yaml.Unmarshal(manifest, &cr)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Printf("unexpected resource kind: %s", meta.Kind)
	}

	cr.rules = make(map[string]rbacv1.PolicyRule)
	for _, rule := range cr.Rules {
		cr.rules[rule.String()] = rule
	}

	return &cr
}

func (cr *ClusterRole) merge(role *ClusterRole) {
	for s, r := range role.rules {
		_, ok := cr.rules[s]
		if !ok {
			cr.rules[s] = r
			cr.Rules = append(cr.Rules, r)
		}
	}
}

func printBoilerplate() {
	fmt.Println(`---
# This is a generated file. DO NOT EDIT
# Run ` + "`make merge-cluster-roles`" + ` to generate.`)
}

func printSources() {
	fmt.Println("# Sources: ")
	for _, source := range os.Args[1:] {
		fmt.Printf("# \t%s\n", source)
	}
}

func printClusterRole(cr *ClusterRole) {
	crManifest, err := yaml.Marshal(&cr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(crManifest))
}

func main() {
	base, err := ioutil.ReadFile(filepath.Clean(os.Args[1]))
	if err != nil {
		log.Fatal(err)
	}
	cr := NewClusterRole(base)

	for _, manifest := range os.Args[2:] {
		data, err := ioutil.ReadFile(filepath.Clean(manifest))
		if err != nil {
			log.Fatal(err)
		}
		cr.merge(NewClusterRole(data))
	}

	// Rules need to be sorted to avoid having an ever changing manifest.
	sort.Slice(cr.Rules, func(i, j int) bool {
		return strings.Compare(cr.Rules[i].String(), cr.Rules[j].String()) < 0
	})

	printBoilerplate()
	printSources()
	printClusterRole(cr)
}
