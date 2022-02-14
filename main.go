/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"

	dockerTypes "github.com/docker/docker/api/types"
	dockerEvents "github.com/docker/docker/api/types/events"
	docker "github.com/moby/docker/client"
)

// DockerPlugin represents our plugin
type DockerPlugin struct {
	plugins.BasePlugin
	FlushInterval uint64 `json:"flushInterval" jsonschema:"description=Flush Interval in ms (Default: 30)"`
}

// DockerInstance represents a opened stream based on our Plugin
type DockerInstance struct {
	source.BaseInstance
	dclient *docker.Client
	msgC    <-chan dockerEvents.Message
	errC    <-chan error
	ctx     context.Context
}

// init function is used for referencing our plugin to the Falco plugin framework
func init() {
	p := &DockerPlugin{}
	extractor.Register(p)
	source.Register(p)
}

// Info displays information of the plugin to Falco plugin framework
func (dockerPlugin *DockerPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                 6,
		Name:               "docker",
		Description:        "Docker Events",
		Contact:            "github.com/falcosecurity/plugins/",
		Version:            "0.1.0",
		RequiredAPIVersion: "0.3.0",
		EventSource:        "docker",
	}
}

// Init is called by the Falco plugin framework as first entry,
// we use it for setting default configuration values and mapping
// values from `init_config` (json format for this plugin)
func (dockerPlugin *DockerPlugin) Init(config string) error {
	dockerPlugin.FlushInterval = 30
	json.Unmarshal([]byte(config), &dockerPlugin)
	return nil
}

// Fields exposes to Falco plugin framework all availables fields for this plugin
func (dockerPlugin *DockerPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "docker.status", Desc: "Status"},
		{Type: "string", Name: "docker.id", Desc: "ID"},
		{Type: "string", Name: "docker.from", Desc: "From"},
		{Type: "string", Name: "docker.type", Desc: "Type"},
		{Type: "string", Name: "docker.action", Desc: "Action"},
		{Type: "string", Name: "docker.stack.namespace", Desc: "Stack Namespace"},
		{Type: "string", Name: "docker.node.id", Desc: "Swarm Node ID"},
		{Type: "string", Name: "docker.swarm.task", Desc: "Swarm Task"},
		{Type: "string", Name: "docker.swarm.taskid", Desc: "Swarm Task ID"},
		{Type: "string", Name: "docker.swarm.taskname", Desc: "Swarm Task Name"},
		{Type: "string", Name: "docker.swarm.servicename", Desc: "Swarm Service Name"},
		{Type: "string", Name: "docker.node.statenew", Desc: "Node New State"},
		{Type: "string", Name: "docker.node.stateold", Desc: "Node Old State"},
		{Type: "string", Name: "docker.attributes.container", Desc: "Attribute Container"},
		{Type: "string", Name: "docker.attributes.image", Desc: "Attribute Image"},
		{Type: "string", Name: "docker.attributes.name", Desc: "Attribute Name"},
		{Type: "string", Name: "docker.attributes.type", Desc: "Attribute Type"},
		{Type: "string", Name: "docker.attributes.exitcode", Desc: "Attribute Exit Code"},
		{Type: "string", Name: "docker.attributes.signal", Desc: "Attribute Signal"},
		{Type: "string", Name: "docker.scope", Desc: "Scope"},
	}
}

// Extract allows Falco plugin framework to get values for all available fields
func (dockerPlugin *DockerPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	var data dockerEvents.Message

	rawData, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	err = json.Unmarshal(rawData, &data)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	switch req.Field() {
	case "docker.status":
		req.SetValue(data.Status)
	case "docker.id":
		req.SetValue(data.ID)
	case "docker.from":
		req.SetValue(data.From)
	case "docker.type":
		req.SetValue(data.Type)
	case "docker.action":
		req.SetValue(data.Action)
	case "docker.scope":
		req.SetValue(data.Scope)
	case "docker.actor.id":
		req.SetValue(data.Actor.ID)
	case "docker.stack.namespace":
		req.SetValue(data.Actor.Attributes["com.docker.stack.namespace"])
	case "docker.swarm.task":
		req.SetValue(data.Actor.Attributes["com.docker.swarm.task"])
	case "docker.swarm.taskid":
		req.SetValue(data.Actor.Attributes["com.docker.swarm.task.id"])
	case "docker.swarm.taskname":
		req.SetValue(data.Actor.Attributes["com.docker.swarm.task.name"])
	case "docker.swarm.servicename":
		req.SetValue(data.Actor.Attributes["com.docker.swarm.service.name"])
	case "docker.node.id":
		req.SetValue(data.Actor.Attributes["com.docker.swarm.node.id"])
	case "docker.node.statenew":
		req.SetValue(data.Actor.Attributes["state.new"])
	case "docker.node.stateold":
		req.SetValue(data.Actor.Attributes["state.old"])
	case "docker.attributes.container":
		req.SetValue(data.Actor.Attributes["container"])
	case "docker.attributes.image":
		req.SetValue(data.Actor.Attributes["image"])
	case "docker.attributes.name":
		req.SetValue(data.Actor.Attributes["name"])
	case "docker.attributes.type":
		req.SetValue(data.Actor.Attributes["type"])
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}

// Open is called by Falco plugin framework for opening a stream of events, we call that an instance
func (dockerPlugin *DockerPlugin) Open(params string) (source.Instance, error) {
	dclient, err := docker.NewClientWithOpts()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	msgC, errC := dclient.Events(ctx, dockerTypes.EventsOptions{})
	return &DockerInstance{
		dclient: dclient,
		msgC:    msgC,
		errC:    errC,
		ctx:     ctx,
	}, nil
}

// String represents the raw value of on event
// (not currently used by Falco plugin framework, only there for future usage)
func (dockerPlugin *DockerPlugin) String(in io.ReadSeeker) (string, error) {
	evtBytes, err := ioutil.ReadAll(in)
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	return fmt.Sprintf("%v", evtStr), nil
}

// NextBatch is called by Falco plugin framework to get a batch of events from the instance
func (dockerInstance *DockerInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {

	dockerPlugin := pState.(*DockerPlugin)

	i := 0
	expire := time.After(time.Duration(dockerPlugin.FlushInterval) * time.Millisecond)
	for i < evts.Len() {
		select {
		case m := <-dockerInstance.msgC:
			s, _ := json.Marshal(m)
			evt := evts.Get(i)
			if _, err := evt.Writer().Write(s); err != nil {
				return i, err
			}
			i++
		case <-expire:
			// Timeout occurred, flush a partial batch
			return i, sdk.ErrTimeout
		case err := <-dockerInstance.errC:
			// todo: this will cause the program to exit. May we want to ignore some kind of error?
			return i, err
		}
	}

	// The batch is full
	return i, nil
}

func (dockerInstance *DockerInstance) Close() {
	dockerInstance.ctx.Done()
}

// main is mandatory but empty, because the plugin will be used as C library by Falco plugin framework
func main() {}
