package main

import (
	docker "github.com/Issif/docker-plugin/pkg"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

const (
	ID          uint32 = 5
	Name               = "docker"
	Description        = "Docker Events"
	Contact            = "github.com/falcosecurity/plugins/"
	Version            = "0.4.0"
	EventSource        = "docker"
)

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &docker.Plugin{}
		p.SetInfo(
			ID,
			Name,
			Description,
			Contact,
			Version,
			EventSource,
		)
		extractor.Register(p)
		source.Register(p)
		return p
	})
}

func main() {}
