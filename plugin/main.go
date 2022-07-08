package main

import (
	docker "github.com/Issif/docker-plugin/pkg"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

const (
	PluginID          uint32 = 5
	PluginName               = "docker"
	PluginDescription        = "Docker Events"
	PluginContact            = "github.com/falcosecurity/plugins/"
	PluginVersion            = "0.2.0"
	PluginEventSource        = "docker"
)

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &docker.Plugin{}
		p.SetInfo(
			PluginID,
			PluginName,
			PluginDescription,
			PluginContact,
			PluginVersion,
			PluginEventSource,
		)
		extractor.Register(p)
		source.Register(p)
		return p
	})
}

func main() {}
