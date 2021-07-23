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
	"context"
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

// TaskRunner manages lists of task groups. Through the RunAll method task groups are
// executed, the groups sequentially, each group of tasks concurrently.
type TaskRunner struct {
	client     *client.Client
	taskGroups []*TaskGroup
}

// NewTaskRunner returns a task runner. tasks is the first task group that will
// be executed, before any list added via AppendTaskGroup.
func NewTaskRunner(client *client.Client, taskGroups ...*TaskGroup) *TaskRunner {
	return &TaskRunner{
		client:     client,
		taskGroups: append([]*TaskGroup{}, taskGroups...),
	}
}

// RunAll executes all registered task groups sequentially. For each group the
// taskGroup.RunConcurrently function is called.
func (tl *TaskRunner) RunAll(ctx context.Context) (string, error) {
	for i, tGroup := range tl.taskGroups {
		klog.V(2).Infof("processing task group %d of %d", i+1, len(tl.taskGroups))

		if name, err := tGroup.RunConcurrently(ctx); err != nil {
			return name, err
		}

	}
	return "", nil
}

// RunConcurrently dispatches all tasks in a task group. The tasks are scheduled
// concurrently. Returns the first error if any are encountered.
func (tg *TaskGroup) RunConcurrently(ctx context.Context) (string, error) {
	var g errgroup.Group
	tgLength := len(tg.tasks)
	for i, ts := range tg.tasks {
		// shadow vars due to concurrency
		ts := ts
		i := i

		g.Go(func() error {
			klog.V(2).Infof("running task %d of %d: %v", i+1, tgLength, ts.Name)
			err := ts.Task.Run(ctx)
			klog.V(2).Infof("ran task %d of %d: %v", i+1, tgLength, ts.Name)
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

func NewTaskGroup(tasks []*TaskSpec) *TaskGroup {
	return &TaskGroup{
		tasks: tasks,
	}
}

type TaskGroup struct {
	tasks []*TaskSpec
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
	Run(ctx context.Context) error
}
type taskErr struct {
	error
	name string
}
