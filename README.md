# README

## Description
The project is the private analysis tool maintained by Nigel. The purpose of project is
create the tool to hunting IOCs during analyzing threat intelligence. 

## Structure
```bash
TI_Analysis
|
|-- analysis
|---- cores
|------ __init__.py
|------ vt_hunter.py
|---- utils
|------ __init__.py
|------ utils_conf.py
|------ utils_log.py
|---- main.py
|---- settings.py
|
|-- conf
|---- log_config.json
|
|-- deploy
|--- flask_app
|------ Dockerfile
|------ requirements.txt
|------ supervisord.conf
|--- nginx
|------ Dockerfile
|------ hunter.conf
|------ nginx.conf
|
|-- envs
|---- cerificate.env
|---- directory.env
|---- network.env
|
|-- log
|---- analysis
|---- nginx
|---- ti_audit
|
|-- .gitignore
|
|-- docker-compose.yaml
|
 -- README.md
```