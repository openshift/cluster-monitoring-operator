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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const commandTimeout time.Duration = 5 * time.Second

type Test struct {
	Script string `yaml:"script"`
	// Only for the test
	TearDown string `yaml:"tearDown"`
}

type Suite struct {
	Tests []Test `yaml:"tests"`
}

func (test *Test) parse() (description string, commands []string) {
	var descLines []string
	scanner := bufio.NewScanner(strings.NewReader(test.Script))
	for scanner.Scan() {
		line := scanner.Text()
		if after, ok := strings.CutPrefix(line, "## "); ok {
			descLines = append(descLines, after)
		} else if strings.TrimSpace(line) != "" {
			commands = append(commands, line)
		}
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	description = strings.Join(descLines, " ")
	return
}

func formatCommands(commands []string) string {
	var sb strings.Builder
	for _, line := range commands {
		// Preserve comments and indented multiline lines.
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, " ") {
			sb.WriteString(line)
		} else {
			sb.WriteString("$ " + line)
		}
		sb.WriteString("\n")
	}
	return strings.TrimSuffix(sb.String(), "\n")
}

type formatter interface {
	formatTest(description string, commands string) string
}

type markdownFormatter struct{}

func (f markdownFormatter) formatTest(description, commands string) string {
	var sb strings.Builder
	sb.WriteString("```\n")
	sb.WriteString("# ")
	sb.WriteString(description)
	sb.WriteString("\n\n")
	sb.WriteString(commands)
	sb.WriteString("\n")
	sb.WriteString("```\n")
	return sb.String()
}

type asciidocFormatter struct{}

func (f asciidocFormatter) formatTest(description, commands string) string {
	var sb strings.Builder
	sb.WriteString("+\n")
	sb.WriteString(description)
	sb.WriteString("\n+\n")
	sb.WriteString("[source,terminal]\n----\n")
	sb.WriteString(commands)
	sb.WriteString("\n----\n")
	return sb.String()
}

func (suite *Suite) format(f formatter) string {
	tests := make([]string, len(suite.Tests))
	for i, t := range suite.Tests {
		description, commands := t.parse()
		tests[i] = f.formatTest(description, formatCommands(commands))
	}
	return strings.Join(tests, "\n")
}

func (suite *Suite) StringMarkdown() string {
	return suite.format(markdownFormatter{})
}

func (suite *Suite) StringAscii() string {
	return suite.format(asciidocFormatter{})
}

func RunScript(t *testing.T, script, wDir, kubeConfigPath string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	cmd.Stderr = bytes.NewBuffer(nil)
	cmd.Dir = wDir
	cmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", kubeConfigPath))
	require.NoError(t, cmd.Run(), "running %s failed: command stderr: %v", script, cmd.Stderr)
}
