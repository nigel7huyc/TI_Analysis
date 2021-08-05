# README

## Description
The project is the private analysis tool maintained by Nigel. The purpose of project is
create the tool to hunting IOCs during analyzing threat intelligence. 

## API Doc
The Doc has been generated automatically, it can be seen used below url
```plain
http://localhost:5000/docs/api/
```

## Structure
```bash
TI_Analysis
|
|-- analysis
|---- cores
|------ __init__.py
|------ vt_files.py
|------ vt_intelligence.py
|---- utils
|------ __init__.py
|------ utils_conf.py
|------ utils_log.py
|------ utils_vt.py
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
|-- output
|---- files
|---- hunting_notifications
|---- pcap
|---- search_results
|
|-- .gitignore
|
|-- docker-compose.yaml
|
 -- README.md
```