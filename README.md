# Docker Events Plugin

This is a POC for a `Falco Plugin` allowing to gather events from a locale `docker` daemon.

> :warning: This is a POC, don't use in Production, join us on Slack **kubernetes#falco** to discuss about.

## Requirements

You need:
* `Go` >= 1.17
* `Falco` >= 0.31
* `json` plugin for `Falco` 

## Build

```shell
make
```

## Configurations

* `falco.yaml`

```yaml
plugins:
  - name: docker
    library_path: /etc/falco/audit/libdocker.so
    init_config: ''
    open_params: ''
  - name: json
    library_path: /etc/falco/json/libjson.so
    init_config: ""

load_plugins: [docker,json]

stdout_output:
  enabled: true
```

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

## Usage

```shell
falco -c falco.yaml -r docker_rules.yaml
```

## Results

```shell
14:53:29.092313000: Debug status=create from=alpine type=container action=create name=pensive_haibt
14:53:29.092787000: Debug status=start from=alpine type=container action=start name=pensive_haibt
14:53:29.092899000: Debug status=die from=alpine type=container action=die name=pensive_haibt
```