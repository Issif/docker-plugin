# Docker Events Plugin

This repository contains the `docker` plugin for `Falco`, which can fetch events and emit sinsp/scap events (e.g. the events used by `Falco`) for each entry.

The plugin also exports fields that extract information from a `docker` event, such as the event time, the action, the container name, the container image, the node id (for `swarm` cluster), ...

- [Docker Events Plugin](#docker-events-plugin)
- [Event Source](#event-source)
- [Supported Fields](#supported-fields)
- [Development](#development)
  - [Requirements](#requirements)
  - [Build](#build)
- [Installation](#installation)
  - [Local](#local)
  - [With falcoctl](#with-falcoctl)
- [Settings](#settings)
- [Configurations](#configurations)
- [Usage](#usage)
  - [Requirements](#requirements-1)
  - [Results](#results)

# Event Source

The event source for `docker` events is `docker`.

# Supported Fields

| Name                          | Type   | Description                    |
| ----------------------------- | ------ | ------------------------------ |
| `docker.status`               | string | Status of the event            |
| `docker.id`                   | string | ID of the event                |
| `docker.from`                 | string | From of the event (deprecated) |
| `docker.type`                 | string | Type of the event              |
| `docker.action`               | string | Action of the event            |
| `docker.stack.namespace`      | string | Stack Namespace                |
| `docker.node.id`              | string | Swarm Node ID                  |
| `docker.swarm.task`           | string | Swarm Task                     |
| `docker.swarm.taskid`         | string | Swarm Task ID                  |
| `docker.swarm.taskname`       | string | Swarm Task Name                |
| `docker.swarm.servicename`    | string | Swarm Service Name             |
| `docker.node.statenew`        | string | Node New State                 |
| `docker.node.stateold`        | string | Node Old State                 |
| `docker.attributes.container` | string | Attribute Container            |
| `docker.attributes.image`     | string | Attribute Image                |
| `docker.attributes.name`      | string | Attribute Name                 |
| `docker.attributes.type`      | string | Attribute Type                 |
| `docker.attributes.exitcode`  | string | Attribute Exit Code            |
| `docker.attributes.signal`    | string | Attribute Signal               |
| `docker.scope`                | string | Scope                          |                                                           

# Development
## Requirements

You need:
* `Go` >= 1.19

## Build

```shell
make build
```

# Installation

## Local

```shell
make install
```
 
## With falcoctl

Add the index:
```shell
sudo falcoctl index add docker https://raw.githubusercontent.com/Issif/docker-plugin/workflow/index.yaml
```

Search for the artifacts:
```shell
sudo falcoctl artifact search docker
```

```shell
INDEX   ARTIFACT        TYPE            REGISTRY        REPOSITORY                              
docker  docker-rules    rulesfile       ghcr.io         issif/docker-plugin/ruleset/docker-rules
docker  docker          plugin          ghcr.io         issif/docker-plugin/plugin/docker 
```

Install the plugin and the rules:
```shell
sudo falcoctl artifact install docker-rules:latest
```

```shell
 INFO  Reading all configured index files from "/root/.config/falcoctl/indexes.yaml"
 INFO  Resolving dependencies ...
 INFO  Installing the following artifacts: [ghcr.io/issif/docker-plugin/ruleset/docker:latest]
 INFO  Preparing to pull "ghcr.io/issif/docker-plugin/ruleset/docker:latest"
 INFO  Pulling c09e07b53699: ############################################# 100% 
 INFO  Pulling 1be5f42ebc40: ############################################# 100% 
 INFO  Pulling 751af53627f8: ############################################# 100% 
 INFO  Artifact successfully installed in "/etc/falco"  
```

# Settings

Only `init` accepts settings:
* `flushinterval`: time en ms between two flushes of events from `docker` to `Falco` (default: 30ms)

# Configurations

* `falco.yaml`

  ```yaml
  plugins:
    - name: docker
      library_path: /usr/share/falco/plugins/libdocker.so
      init_config: '{"flushinterval": 10}'
      open_params: ''

  load_plugins: [docker]

  stdout_output:
    enabled: true
  ```
  > :bulb: `init_config` can also set in `yaml` format:
  > ```yaml
  > init_config:
  >   flushinterval: 10
  > ```

* `rules.yaml`

The `source` for rules must be `docker`.

See example:
```yaml
- rule: Dummy Rule
  desc: Dummy Rule
  condition: docker.status in (start,create,die)
  output: status=%docker.status from=%docker.from type=%docker.type action=%docker.action name=%docker.attributes.name 
  priority: DEBUG
  source: docker
  tags: [docker]
```

# Usage

```shell
falco -c falco.yaml -r docker_rules.yaml
```

## Requirements

* `Falco` >= 0.34

## Results

```shell
14:53:29.092313000: Debug status=create from=alpine type=container action=create name=pensive_haibt
14:53:29.092787000: Debug status=start from=alpine type=container action=start name=pensive_haibt
14:53:29.092899000: Debug status=die from=alpine type=container action=die name=pensive_haibt
```