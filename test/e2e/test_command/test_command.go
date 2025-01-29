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
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"strings"

	"github.com/mattn/go-shellwords"
	"github.com/stretchr/testify/require"
)

var commandTimeout time.Duration = 5 * time.Second

type SetUpTearDownCommand struct {
	// This isn't run in a shell.
	Command string `yaml:"run"`
	EnvVar  string `yaml:"toEnvVar"`
	// the Commands' stdout
	envVarValue string
}

type CheckCommand struct {
	// This isn't run in a shell.
	Command string `yaml:"run"`
}

type Test struct {
	Header string `yaml:"header"`
	// Run by a user having the needed permissions.
	// Env vars defined in SetUp, can only be used in Checks
	SetUp []SetUpTearDownCommand `yaml:"setUp"`
	//
	Checks []CheckCommand `yaml:"checks"`

	TearDown []SetUpTearDownCommand `yaml:"tearDown"`
}

type Suite struct {
	Tests []Test `yaml:"tests"`
}

func (stc *SetUpTearDownCommand) String() string {
	if stc.EnvVar != "" {
		return fmt.Sprintf("$ %s=$(%s)", stc.EnvVar, stc.Command)
	}
	return fmt.Sprintf("$ %s", stc.Command)
}

func (stc *SetUpTearDownCommand) EnvVarValue() string {
	return stc.envVarValue
}

func (cc *CheckCommand) String() string {
	return fmt.Sprintf("$ %s", cc.Command)
}

func (test *Test) String() string {
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(test.Header)
	for _, s := range test.SetUp {
		sb.WriteString("\n")
		sb.WriteString(s.String())
	}
	for _, c := range test.Checks {
		sb.WriteString("\n")
		sb.WriteString(c.String())
	}
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

func (stc *SetUpTearDownCommand) Run(t *testing.T, wDir, kubeConfigPath string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	args, err := shellwords.Parse(stc.Command)
	require.NoError(t, err)

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stderr = bytes.NewBuffer(nil)
	cmd.Dir = wDir
	cmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", kubeConfigPath))

	if stc.EnvVar != "" {
		out, err := cmd.Output()
		require.NoError(t, err, "getting stdout failed: %v: command stderr %v", err, cmd.Stderr)
		stc.envVarValue = string(out)
		return nil
	}

	require.NoError(t, cmd.Run(), "running %s failed: command stderr: %v", stc.Command, cmd.Stderr)
	return nil
}

func (cc *CheckCommand) Run(t *testing.T, wDir, kubeConfigPath string, envVars map[string]string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	parser := shellwords.NewParser()
	// To avoid running a shell.
	parser.ParseEnv = true
	envVars["KUBECONFIG"] = kubeConfigPath
	parser.Getenv = func(s string) string { return envVars[s] }
	args, err := parser.Parse(cc.Command)
	require.NoError(t, err)

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stderr = bytes.NewBuffer(nil)
	cmd.Dir = wDir

	require.NoError(t, cmd.Run(), "running %s failed: command stderr: %v", cc.Command, cmd.Stderr)
	return nil
}
