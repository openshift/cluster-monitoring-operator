// Copyright 2024 The Cluster Monitoring Operator Authors
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

package test_command

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"strings"

	"github.com/stretchr/testify/require"
)

var commandTimeout time.Duration = 5 * time.Second

type Test struct {
	Script string `yaml:"script"`
	// Only for the test
	TearDown string `yaml:"tearDown"`
	// The test should run inside the cluster.
	InCluster bool `yaml:"inCluster"`
}

type Suite struct {
	Tests []Test `yaml:"tests"`
}

func (test *Test) String() string {
	var sb strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(test.Script))
	for scanner.Scan() {
		sb.WriteString("\n")
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, " ") {
			sb.WriteString(line)
			continue
		}
		sb.WriteString(fmt.Sprintf("$ %s", line))
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	sb.WriteString("\n")
	return sb.String()
}

func (suite *Suite) intoCodeBlocks(delimiter string) string {
	var sb strings.Builder
	for _, t := range suite.Tests {
		sb.WriteString(delimiter)
		sb.WriteString(t.String())
		sb.WriteString(delimiter)
		sb.WriteString("\n")
	}
	return sb.String()
}

func (suite *Suite) StringMarkdown() string {
	return suite.intoCodeBlocks("```")
}

func (suite *Suite) StringAscii() string {
	// Not ready to be part of the doc yet.
	return ""
	// return suite.intoCodeBlocks("----")
}

func RunScript(t *testing.T, script, wDir, kubeConfigPath string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, shell(), "-c", script)
	cmd.Stderr = bytes.NewBuffer(nil)
	cmd.Dir = wDir
	cmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", kubeConfigPath))
	require.NoError(t, cmd.Run(), "running %s failed: command stderr: %v", script, cmd.Stderr)
}

func shell() string {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "sh"
	}
	return shell
}
