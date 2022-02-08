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
	"math"
	"time"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"

	dockerTypes "github.com/docker/docker/api/types"
	dockerEvents "github.com/docker/docker/api/types/events"
	docker "github.com/moby/docker/client"
)

type MyPluginConfig struct {
	TimeWindow string `json:"timeWindow" jsonschema:"description=Time Window (Default: 2s)"`
}

type MyPlugin struct {
	plugins.BasePlugin
	config MyPluginConfig
	number uint64
}

type MyInstance struct {
	source.BaseInstance
	timeWindow string
	buffer     *chan []byte
}

func init() {
	p := &MyPlugin{}
	extractor.Register(p)
	source.Register(p)
}

func (p *MyPluginConfig) setDefault() {
	p.TimeWindow = "2s"
}

func (m *MyPlugin) Info() *plugins.Info {
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

func (m *MyPlugin) InitSchema() *sdk.SchemaInfo {
	schema, err := jsonschema.Reflect(&MyPluginConfig{}).MarshalJSON()
	if err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

func (m *MyPlugin) Init(config string) error {
	m.number = math.MaxUint64
	m.config.setDefault()
	json.Unmarshal([]byte(config), &m.config)
	return nil
}

func (m *MyPlugin) Fields() []sdk.FieldEntry {
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

func (p *MyPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
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

func (m *MyPlugin) Open(params string) (source.Instance, error) {
	return &MyInstance{
		timeWindow: m.config.TimeWindow,
		buffer:     new(chan []byte),
	}, nil
}

func (m *MyPlugin) String(in io.ReadSeeker) (string, error) {
	evtBytes, err := ioutil.ReadAll(in)
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	return fmt.Sprintf("%v", evtStr), nil
}

func (m *MyInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	dclient, err := docker.NewClientWithOpts()
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	defer ctx.Done()

	msg, _ := dclient.Events(ctx, dockerTypes.EventsOptions{})

	e := [][]byte{}

L:
	for {
		expire := time.After(2 * time.Second)
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

func main() {}
