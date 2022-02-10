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
	"os"
	"os/signal"
	"syscall"
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
	FlushInterval uint64 `json:"flush_interval" jsonschema:"description=Flush Interval in seconds (Default: 2)"`
}

// DockerInstance represents a opened stream based on our Plugin
type DockerInstance struct {
	source.BaseInstance
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
	dockerPlugin.FlushInterval = 2
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
		{Type: "string", Name: "docker.actor.id", Desc: "Actor ID"},
		{Type: "string", Name: "docker.attributes.container", Desc: "Attribute Container"},
		{Type: "string", Name: "docker.attributes.image", Desc: "Attribute Image"},
		{Type: "string", Name: "docker.attributes.name", Desc: "Attribute Name"},
		{Type: "string", Name: "docker.attributes.type", Desc: "Attribute Type"},
		{Type: "string", Name: "docker.attributes.exitcode", Desc: "Attribute Exit Code"},
		{Type: "string", Name: "docker.scope", Desc: "Scope"},
	}
}

// Extracts allows Falco plugin framework to get values for all available fields
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
	return &DockerInstance{}, nil
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
	dclient, err := docker.NewClientWithOpts()
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	defer ctx.Done()

	msg, _ := dclient.Events(ctx, dockerTypes.EventsOptions{})

	e := [][]byte{}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	dockerPlugin := pState.(*DockerPlugin)

L:
	for {
		expire := time.After(time.Duration(dockerPlugin.FlushInterval) * time.Second)
		select {
		case m := <-msg:
			s, _ := json.Marshal(m)
			e = append(e, s)
			if len(e) >= evts.Len() {
				break L
			}
		case <-expire:
			if len(e) != 0 {
				break L
			}
		case <-c:
			return 0, sdk.ErrEOF
		}
	}

	if len(e) == 0 {
		return 0, nil
	}

	for n, i := range e {
		evt := evts.Get(n)
		_, err := evt.Writer().Write(i)
		if err != nil {
			return 0, err
		}
	}

	return len(e), nil
}

// main is mandatory but empty, because the plugin will be used as C library by Falco plugin framework
func main() {}
