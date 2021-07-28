# gatekeeper
An iptables based port forwarding API server

Check wiki for API Documentation [Wiki](https://github.com/IRIS-NITK/gatekeeper/wiki)

## Setup
- Setup virtual environment and install packages listed in requirements.txt
- Create .env by copying .ev.example
- Update the environment variables in .env.example
- create database, apply migrations
- Enable port forwarding 
- start celery worker ```celery -A portforwarder worker --loglevel=INFO```
- Run the django server as root user