package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/test_command"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"
	k8syaml "sigs.k8s.io/yaml"

	"bufio"

	"gopkg.in/yaml.v3"
)

type docTemplate struct {
	introduction string
	section      string
}

var (
	markDownTemplate = docTemplate{
		introduction: `This document describes the following resources deployed and managed by the Cluster Monitoring Operator (CMO):

* Routes
* Services

Important!

In certain situations, accessing endpoints can degrade the performance and scalability of your cluster, especially if you use endpoints to retrieve, send, or query large amounts of metrics data.

To avoid these issues, follow these recommendations:

* Avoid querying endpoints frequently. Limit queries to a maximum of one every 30 seconds.
* Do not try to retrieve all metrics data via the /federate endpoint. Query it only when you want to retrieve a limited, aggregated data set. For example, retrieving fewer than 1,000 samples for each request helps minimize the risk of performance degradation.

`,
		section: `## {{ .Kind }}s

{{ range .Resources -}}
### {{ .Namespace }}/{{ .Name }}

{{ .Description }}

{{ end -}}
`,
	}

	asciiDocsTemplate = docTemplate{
		introduction: `// DO NOT EDIT THE CONTENT IN THIS FILE. It is automatically generated from the
// source code for the Cluster Monitoring Operator. Any changes made to this
// file will be overwritten when the content is regenerated. If you wish to
// make edits or learn more about how this file is generated, read the docgen utility
// instructions in the source code for the CMO.
:_mod-docs-content-type: REFERENCE
[id="resources-reference-for-the-cluster-monitoring-operator"]
= Resources reference for the Cluster Monitoring Operator
include::_attributes/common-attributes.adoc[]
:context: resources-reference-for-the-cluster-monitoring-operator

toc::[]

[id="Cluster-monitoring-resources-reference"]
== Cluster monitoring resources reference
This document describes the following resources deployed and managed by the Cluster Monitoring Operator (CMO):

* link:#cmo-routes-resources[Routes]
* link:#cmo-services-resources[Services]

Use this information when you want to configure API endpoint connections to retrieve, send, or query metrics data.

[IMPORTANT]
====
In certain situations, accessing endpoints can degrade the performance and scalability of your cluster, especially if you use endpoints to retrieve, send, or query large amounts of metrics data.

To avoid these issues, follow these recommendations:

* Avoid querying endpoints frequently. Limit queries to a maximum of one every 30 seconds.
* Do not try to retrieve all metrics data via the /federate endpoint. Query it only when you want to retrieve a limited, aggregated data set. For example, retrieving fewer than 1,000 samples for each request helps minimize the risk of performance degradation.
====
`,
		section: `[id="cmo-{{ .Kind | toLower }}s-resources"]
== CMO {{ .Kind | toLower }}s resources

{{ range .Resources -}}
=== {{ .Namespace }}/{{ .Name }}

{{ .Description }}

{{ end -}}
`,
	}
)

type data struct {
	Kind      string
	Resources []resource
}

type resource struct {
	Name        string
	Namespace   string
	Description string
}

func findYAMLFiles(dir string) ([]string, error) {
	var files []string
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}

		if !strings.HasSuffix(d.Name(), ".yaml") {
			return nil
		}

		files = append(files, path)
		return nil
	}); err != nil {
		return nil, err
	}

	return files, nil
}

func PrintManagedResources(format string) error {
	var files []string
	for _, d := range []string{"assets", "manifests"} {
		f, err := findYAMLFiles(d)
		if err != nil {
			return err
		}
		files = append(files, f...)
	}
	sort.Strings(files)

	resourcesByKind := map[string][]resource{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}

		var o unstructured.Unstructured
		err = k8syaml.UnmarshalStrict(b, &o)
		if err != nil {
			return err
		}

		a := o.GetAnnotations()
		if len(a) == 0 {
			continue
		}

		desc, found := a[manifests.DescriptionAnnotation]
		if !found {
			continue
		}

		desc, err = substitutePlaceholdersInDescription(desc, format)
		if err != nil {
			return err
		}

		resourcesByKind[o.GetKind()] = append(
			resourcesByKind[o.GetKind()],
			resource{
				Name:        o.GetName(),
				Namespace:   o.GetNamespace(),
				Description: desc,
			},
		)
	}

	if format == asciiDocsFormat {
		return printDoc(asciiDocsTemplate, resourcesByKind)
	}

	return printDoc(markDownTemplate, resourcesByKind)
}

func orderedKeys(m map[string][]resource) []string {
	kinds := sets.New[string]()
	for k := range m {
		kinds.Insert(k)
	}

	return sets.List[string](kinds)
}

func printDoc(dt docTemplate, m map[string][]resource) error {
	t := template.Must(template.New("").Parse(dt.introduction))
	if err := t.Execute(os.Stdout, nil); err != nil {
		return err
	}

	for _, k := range orderedKeys(m) {
		d := data{
			Kind:      k,
			Resources: m[k],
		}

		t := template.Must(template.New("").Funcs(template.FuncMap{
			"toLower": strings.ToLower,
		}).Parse(dt.section))
		if err := t.Execute(os.Stdout, &d); err != nil {
			return err
		}
	}

	return nil
}

// substitutePlaceholdersInDescription replaces the tested example placeholder by its content.
func substitutePlaceholdersInDescription(desc, format string) (string, error) {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(desc))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, manifests.TestFilePlacehoderPrefix) {
			lines = append(lines, line)
			continue
		}
		fileName := strings.TrimPrefix(line, manifests.TestFilePlacehoderPrefix)
		file, err := os.Open(filepath.Join("test", "e2e", "test_command", "scripts", fileName))
		if err != nil {
			return "", err
		}
		defer file.Close()

		var suite test_command.Suite
		decoder := yaml.NewDecoder(file)
		decoder.KnownFields(true)
		err = decoder.Decode(&suite)
		if err != nil {
			return "", err
		}

		// Replace the line with the file content
		var content string
		if format == asciiDocsFormat {
			content = suite.StringAscii()
		} else {
			content = suite.StringMarkdown()
		}
		lines = append(lines, content)
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return strings.Join(lines, "\n"), nil
}
