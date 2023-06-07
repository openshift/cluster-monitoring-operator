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
	"fmt"
	"strings"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
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

func (tl *TaskRunner) RunAll(ctx context.Context) TaskGroupErrors {
	for i, tGroup := range tl.taskGroups {
		klog.V(2).Infof("processing task group %d of %d", i+1, len(tl.taskGroups))
		tErrors := tGroup.RunConcurrently(ctx)
		if len(tErrors) > 0 {
			return tErrors
		}
	}
	return nil
}

// RunConcurrently dispatches all tasks in a task group. The tasks are scheduled
// concurrently. Returns all the errors that are encountered.
func (tg *TaskGroup) RunConcurrently(ctx context.Context) TaskGroupErrors {
	var g errgroup.Group
	tgLength := len(tg.tasks)
	errChan := make(chan TaskErr, tgLength)
	for i, ts := range tg.tasks {
		// shadow vars due to concurrency
		ts := ts
		i := i

		g.Go(func() error {
			klog.V(2).Infof("running task %d of %d: %v", i+1, tgLength, ts.Name)
			err := ts.Task.Run(ctx)
			if err != nil {
				klog.Warningf("task %d of %d: %v failed: %v", i+1, tgLength, ts.Name, err)
				errChan <- TaskErr{Err: err, Name: ts.Name}
			} else {
				klog.V(2).Infof("ran task %d of %d: %v", i+1, tgLength, ts.Name)
			}
			return nil
		})
	}

	//nolint:errcheck
	g.Wait()
	// To be able to use the range function on the buffered channel
	// the channel needs to closed. Otherwise the range will keep waiting
	// till the channel is closed. This is why defer is not used.
	close(errChan)
	var taskGroupErrors TaskGroupErrors
	for tErr := range errChan {
		taskGroupErrors = append(taskGroupErrors, tErr)
	}

	return taskGroupErrors
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

type TaskErr struct {
	Err  error
	Name string
}

type TaskGroupErrors []TaskErr

func (tge TaskGroupErrors) Error() string {
	if len(tge) == 0 {
		return ""
	}
	messages := make([]string, 0, len(tge))
	for _, err := range tge {
		messages = append(messages, fmt.Sprintf("%v: %v", strings.ToLower(err.Name), err.Err))
	}
	return strings.Join(messages, "\n")
}
