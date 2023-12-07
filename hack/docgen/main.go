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
	"os"

	"github.com/openshift/cluster-monitoring-operator/hack/docgen/format/asciidocs"
	"github.com/openshift/cluster-monitoring-operator/hack/docgen/format/markdown"
)

const (
	markDownFormat  = "markdown"
	asciiDocsFormat = "asciidocs"
)

func main() {
	var (
		cmd    = os.Args[1]
		format = os.Args[2]
	)

	if format != markDownFormat && format != asciiDocsFormat {
		fmt.Fprintf(os.Stderr, "Unsupported format %q, supported formats are: %q or %q\n", os.Args[2], markDownFormat, asciiDocsFormat)
		os.Exit(1)
	}

	switch cmd {
	case "api":
		switch format {
		case markDownFormat:
			markdown.PrintAPIDocs(os.Args[3:])
		case asciiDocsFormat:
			asciidocs.PrintAPIDocs(os.Args[3:])
		}
	case "resources":
		if err := PrintManagedResources(format); err != nil {
			fmt.Fprintf(os.Stderr, "failed to print managed resources: %s\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unsupported command %q, supported commands are: api or resources\n", cmd)
		os.Exit(1)
	}
}
