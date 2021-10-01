// Copyright 2016 The prometheus-operator Authors
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
	"bytes"
	"container/list"
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
)

const (
	firstParagraph = `
// NOTE: The contents of this file are automatically generated from source code comments.
// If you wish to make a change or an addition to the content in this document, do so by changing the code comments.

= Config map fields for the Cluster Monitoring Operator 

The following tables describe fields that you can use in config map objects for the Cluster Monitoring Operator. These fields enable you to do fine-grained configuration of platform monitoring and user workload monitoring.`
)

var (
	links = map[string]string{
		"v1.SecretKeySelector":              "https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#secretkeyselector-v1-core",
		"monv1.MetadataConfig":              "https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#metadataconfig",
		"monv1.SafeTLSConfig":               "https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#safetlsconfig",
		"v1.ResourceRequirements":           "https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#resourcerequirements-v1-core",
		"v1.Toleration":                     "https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#toleration-v1-core",
		"v12.EmbeddedPersistentVolumeClaim": "https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#embeddedpersistentvolumeclaim",
		"monv1.QueueConfig":                 "https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#queueconfig",
		"monv1.RelabelConfig":               "https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#relabelconfig",
		"monv1.BasicAuth":                   "https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#basicauth",
	}

	selfLinks     = map[string]string{}
	typesDoc      = map[string]KubeTypes{}
	nameKubeTypes = map[string]KubeTypes{}
)

func toSectionLink(name string) string {
	name = strings.ToLower(name)
	name = strings.Replace(name, " ", "-", -1)
	return name
}

func printTOC(types []KubeTypes) {
	fmt.Printf("\n### Table of Contents\n")
	for _, t := range types {
		strukt := t[0]
		if len(t) > 1 {
			fmt.Printf("* [%s](#%s)\n", strukt.Name, toSectionLink(strukt.Name))
		}
	}
}

func printAPIDocs(paths []string) {
	fmt.Println(firstParagraph)

	types, _ := ParseDocumentationFrom(paths)
	for _, t := range types {
		strukt := t[0]
		selfLinks[strukt.Name] = "#" + strings.ToLower(strukt.Name)
		typesDoc[toLink(strukt.Name)] = t[1:]
	}

	// we need to parse once more to now add the self links and the inlined fields
	types, typesIndex := ParseDocumentationFrom(paths)

	printConfigs("ClusterMonitoringConfiguration", typesIndex)
	printConfigs("UserWorkloadConfiguration", typesIndex)
}

func printConfigs(configType string, typesIndex map[string][]string) {
	var (
		orderedTypes []KubeTypes
		queue        = list.New()
		struktExist  = map[string]bool{}
	)
	pmOrUwmStrukt := nameKubeTypes[configType]

	fmt.Printf("\n== %s\n\n", configType)

	for _, field := range pmOrUwmStrukt[1:] {
		fieldType := getStructType(field.Type)
		if selfLinks[fieldType] != "" && struktExist[fieldType] == false {
			struktExist[fieldType] = true
			orderedTypes = append(orderedTypes, nameKubeTypes[fieldType])
			queue.PushBack(nameKubeTypes[fieldType])
		}
	}

	findDependentStructs(&orderedTypes, queue, struktExist)

	//printTOC(orderedTypes)
	for _, t := range orderedTypes {
		strukt := t[0]
		if len(t) > 1 {
			fmt.Printf("\n.%s\t[%s]\n", strukt.Name, strukt.Doc)
			//appearsIn := typesIndex[strukt.Name]
			//if len(appearsIn) > 0 {
			//	relatedLinks := make([]string, 0, len(appearsIn))
			//	for _, inType := range appearsIn {
			//		link := fmt.Sprintf("[%s](#%s)", inType, toSectionLink(inType))
			//		relatedLinks = append(relatedLinks, link)
			//	}
			//	fmt.Printf("\n<em>appears in: %s</em>\n\n", strings.Join(relatedLinks, ", "))
			//}
			fmt.Println("|===")
			fmt.Println("| Field | Description | Scheme | Required | Status")
			fmt.Println()
			//fmt.Println("| ----- | ----------- | ------ | -------- | --------")
			fields := t[1:]
			for _, f := range fields {
				fmt.Println("|", f.Name, "|", f.Doc, "|", f.Type, "|", f.Mandatory, "|", f.Status)
			}
			fmt.Println("|===")
			fmt.Println("")
		}
	}
}

func findDependentStructs(orderedTypes *[]KubeTypes, queue *list.List, struktExist map[string]bool) {
	for queue.Len() > 0 {
		element := queue.Front()
		strukt := element.Value.(KubeTypes)
		for _, t := range strukt[1:] {
			fieldType := getStructType(t.Type)
			if selfLinks[fieldType] != "" && struktExist[fieldType] == false {
				struktExist[fieldType] = true
				*orderedTypes = append(*orderedTypes, nameKubeTypes[fieldType])
				queue.PushBack(nameKubeTypes[fieldType])
			}
		}
		queue.Remove(element)
	}
}

// KubeType of strings. We keed the name of fields and the doc
type KubeType struct {
	Name, Doc, Type, Status string
	Mandatory               bool
}

// KubeTypes is an array to represent all available types in a parsed file. [0] is for the type itself
type KubeTypes []KubeType

// ParseDocumentationFrom gets all types' documentation and returns them as an
// array. Each type is again represented as an array (we have to use arrays as we
// need to be sure for the order of the fields). This function returns fields and
// struct definitions that have no documentation as {name, ""}.
func ParseDocumentationFrom(srcs []string) ([]KubeTypes, map[string][]string) {
	var docForTypes []KubeTypes
	typesIndex := make(map[string][]string)

	for _, src := range srcs {
		pkg := astFrom(src)

		for _, kubType := range pkg.Types {
			if structType, ok := kubType.Decl.Specs[0].(*ast.TypeSpec).Type.(*ast.StructType); ok {
				if kubType.Name != "ClusterMonitoringConfiguration" && kubType.Name != "UserWorkloadConfiguration" {
					for _, fieldName := range getFieldNames(structType) {
						typesIndex[fieldName] = append(typesIndex[fieldName], kubType.Name)
					}
				}

				var ks KubeTypes
				ks = append(ks, KubeType{kubType.Name, fmtRawDoc(kubType.Doc), "", "", false})

				for _, field := range structType.Fields.List {
					// Treat inlined fields separately as we don't want the original types to appear in the doc.
					if isInlined(field) {
						// Skip external types, as we don't want their content to be part of the API documentation.
						if isInternalType(field.Type) {
							ks = append(ks, typesDoc[fieldType(field.Type)]...)
						}
						continue
					}
					typeString := fieldType(field.Type)
					fieldMandatory := fieldRequired(field)
					fieldStatus := fieldStatus(field)
					if n := fieldName(field); n != "-" {
						fieldDoc := fmtRawDoc(field.Doc.Text())
						ks = append(ks, KubeType{n, fieldDoc, typeString, fieldStatus, fieldMandatory})
					}
				}
				nameKubeTypes[kubType.Name] = ks
				docForTypes = append(docForTypes, ks)
			}
		}
	}

	return docForTypes, typesIndex
}

func astFrom(filePath string) *doc.Package {
	fset := token.NewFileSet()
	m := make(map[string]*ast.File)

	f, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	m[filePath] = f
	apkg, _ := ast.NewPackage(fset, m, nil, nil)

	return doc.New(apkg, "", 0)
}

func fmtRawDoc(rawDoc string) string {
	var buffer bytes.Buffer
	delPrevChar := func() {
		if buffer.Len() > 0 {
			buffer.Truncate(buffer.Len() - 1) // Delete the last " " or "\n"
		}
	}

	// Ignore all lines after ---
	rawDoc = strings.Split(rawDoc, "---")[0]

	for _, line := range strings.Split(rawDoc, "\n") {
		line = strings.TrimRight(line, " ")
		leading := strings.TrimLeft(line, " ")
		switch {
		case len(line) == 0: // Keep paragraphs
			delPrevChar()
			buffer.WriteString("\n\n")
		case strings.HasPrefix(leading, "TODO"): // Ignore one line TODOs
		case strings.HasPrefix(leading, "+"): // Ignore instructions to go2idl
		default:
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				delPrevChar()
				line = "\n" + line + "\n" // Replace it with newline. This is useful when we have a line with: "Example:\n\tJSON-someting..."
			} else {
				line += " "
			}
			buffer.WriteString(line)
		}
	}

	postDoc := strings.TrimRight(buffer.String(), "\n")
	postDoc = strings.Replace(postDoc, "\\\"", "\"", -1) // replace user's \" to "
	postDoc = strings.Replace(postDoc, "\"", "\\\"", -1) // Escape "
	postDoc = strings.Replace(postDoc, "\n", "\\n", -1)
	postDoc = strings.Replace(postDoc, "\t", "\\t", -1)
	postDoc = strings.Replace(postDoc, "|", "\\|", -1)

	return postDoc
}

func toLink(typeName string) string {
	selfLink, hasSelfLink := selfLinks[typeName]
	if hasSelfLink {
		return wrapInLink(typeName, selfLink)
	}

	link, hasLink := links[typeName]
	if hasLink {
		return wrapInLink(typeName, link)
	}

	return typeName
}

func wrapInLink(text, link string) string {
	return fmt.Sprintf("[%s](%s)", text, link)
}

func isInlined(field *ast.Field) bool {
	jsonTag := reflect.StructTag(field.Tag.Value[1 : len(field.Tag.Value)-1]).Get("json") // Delete first and last quotation
	return strings.Contains(jsonTag, "inline")
}

func isInternalType(typ ast.Expr) bool {
	switch typ := typ.(type) {
	case *ast.SelectorExpr:
		pkg := typ.X.(*ast.Ident)
		return strings.HasPrefix(pkg.Name, "monitoring")
	case *ast.StarExpr:
		return isInternalType(typ.X)
	case *ast.ArrayType:
		return isInternalType(typ.Elt)
	case *ast.MapType:
		return isInternalType(typ.Key) && isInternalType(typ.Value)
	default:
		return true
	}
}

// fieldName returns the name of the field as it should appear in JSON format
// "-" indicates that this field is not part of the JSON representation
func fieldName(field *ast.Field) string {
	jsonTag := reflect.StructTag(field.Tag.Value[1 : len(field.Tag.Value)-1]).Get("json") // Delete first and last quotation
	jsonTag = strings.Split(jsonTag, ",")[0]                                              // This can return "-"
	if jsonTag == "" {
		if field.Names != nil {
			return field.Names[0].Name
		}
		return field.Type.(*ast.Ident).Name
	}
	return jsonTag
}

func fieldStatus(field *ast.Field) string {
	statusTag := ""

	if field.Tag != nil {
		statusTag = reflect.StructTag(field.Tag.Value[1 : len(field.Tag.Value)-1]).Get("status")
		switch statusTag {
		case "":
			return "GA"
		case "TechPreview":
			return "Tech Preview"
		}
	}
	return statusTag
}

// fieldRequired returns whether a field is a required field.
func fieldRequired(field *ast.Field) bool {
	jsonTag := ""
	if field.Tag != nil {
		jsonTag = reflect.StructTag(field.Tag.Value[1 : len(field.Tag.Value)-1]).Get("json") // Delete first and last quotation
		return !strings.Contains(jsonTag, "omitempty")
	}

	return false
}

func fieldType(typ ast.Expr) string {
	switch typ := typ.(type) {
	case *ast.Ident:
		return typ.Name
	case *ast.StarExpr:
		return "*" + fieldType(typ.X)
	case *ast.SelectorExpr:
		pkg := typ.X.(*ast.Ident)
		t := typ.Sel
		return pkg.Name + "." + t.Name
	case *ast.ArrayType:
		return "[]" + fieldType(typ.Elt)
	case *ast.MapType:
		return "map[" + fieldType(typ.Key) + "]" + fieldType(typ.Value)
	default:
		return ""
	}
}

func getFieldNames(structType *ast.StructType) []string {
	var fieldNames []string
	foundFields := make(map[string]struct{})

	for _, ft := range structType.Fields.List {
		fieldName := getFieldName(ft.Type)
		// Field name not identified, continue
		if fieldName == "" {
			continue
		}

		// Skip if field has already been found in the struct
		if _, ok := foundFields[fieldName]; ok {
			continue
		}

		fieldNames = append(fieldNames, fieldName)
		foundFields[fieldName] = struct{}{}
	}

	return fieldNames
}

func getFieldName(ft ast.Expr) string {
	switch ft := ft.(type) {
	case *ast.Ident:
		return ft.Name
	case *ast.ArrayType:
		return getFieldName(ft.Elt)
	case *ast.StarExpr:
		return getFieldName(ft.X)
	}

	return ""
}

func getStructType(structType string) string {
	if strings.HasPrefix(structType, "*") {
		return strings.Split(structType, "*")[1]
	} else if strings.HasPrefix(structType, "[]") {
		return strings.Split(structType, "[]")[1]
	}

	return structType

}
