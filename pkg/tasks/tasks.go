// Copyright 2018 The Cluster Monitoring Operator Authors
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

package tasks

import (
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

type TaskRunner struct {
	client *client.Client
	tasks  []*TaskSpec
}

func NewTaskRunner(client *client.Client, tasks []*TaskSpec) *TaskRunner {
	return &TaskRunner{
		client: client,
		tasks:  tasks,
	}
}

func (tl *TaskRunner) RunAll() (string, error) {
	var g errgroup.Group
	for i, ts := range tl.tasks {
		// shadow vars due to concurrency
		ts := ts
		i := i

		g.Go(func() error {
			klog.V(2).Infof("running task %d of %d: %v", i+1, len(tl.tasks), ts.Name)
			err := tl.ExecuteTask(ts)
			klog.V(2).Infof("ran task %d of %d: %v", i+1, len(tl.tasks), ts.Name)
			if err != nil {
				return taskErr{error: errors.Wrapf(err, "running task %v failed", ts.Name), name: ts.Name}
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		taskName := ""
		if tErr, ok := err.(taskErr); ok {
			taskName = tErr.name
			err = tErr.error

		}
		return taskName, err
	}
	return "", nil
}

func (tl *TaskRunner) ExecuteTask(ts *TaskSpec) error {
	return ts.Task.Run()
}

func NewTaskSpec(name string, task Task) *TaskSpec {
	return &TaskSpec{
		Name: name,
		Task: task,
	}
}

type TaskSpec struct {
	Name string
	Task Task
}

type Task interface {
	Run() error
}

type taskErr struct {
	error
	name string
}
