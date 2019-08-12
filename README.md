# NuvlaBox Agent

[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg?style=for-the-badge)](https://github.com/nuvlabox/agent/graphs/commit-activity)


[![CI](https://img.shields.io/travis/com/nuvlabox/agent?style=for-the-badge&logo=travis-ci&logoColor=white)](https://travis-ci.com/nuvlabox/agent)
[![GitHub issues](https://img.shields.io/github/issues/nuvlabox/agent?style=for-the-badge&logo=github&logoColor=white)](https://GitHub.com/nuvlabox/agent/issues/)
[![Docker pulls](https://img.shields.io/docker/pulls/nuvlabox/agent?style=for-the-badge&logo=Docker&logoColor=white)](https://cloud.docker.com/u/nuvlabox/repository/docker/nuvlabox/agent)
[![Docker image size](https://img.shields.io/microbadger/image-size/nuvlabox/agent?style=for-the-badge&logo=Docker&logoColor=white)](https://cloud.docker.com/u/nuvlabox/repository/docker/nuvlabox/agent)

![logo](https://uc977612ad25e6fb53ac9275cd4c.previews.dropboxusercontent.com/p/thumb/AAhLDh0-m61kGliju2bmLxVEc36VssSKVjGd9r6JnxmpdVExwfKsZWXtVtc2gz0IR1PN7tviqaJJY3YSXHZhxTwO1x_8bHHt3W49SZDgrMqPW84Jw9vg-Dmv_2J4siLp44GvufcOPr8Rw96xIGfG1JIm_xrADjdl0tpgW8LrJnojoMl5l7hCs0cNLMQm54P_QH8hhg5cc8Nkvk2M5F5YBp4MM5M62AMQXZRihBz4QsbvHeVNIj3Z8lI-gbcY9rYjiQmLYeAdP_REq2eEYcrADrMHHI6oJRuFQAAzrEPcyc6_3KQzMENiGflpKZAE2BcAJAJ956KodJjixpH8PPC_3sGlhijEZ2LTE_jwb00-znmVRV-BYNr8MO16HCZIBQeRgSc/p.png?fv_content=true&size_mode=5)


**This repository contains the source code for the NuvlaBox Agent - the microservice which is responsible for the [NuvlaBox](https://sixsq.com/products-and-services/nuvlabox/overview) activation, categorization and telemetry. **

This microservice is an integral component of the NuvlaBox Engine.

---

**NOTE:** this microservice is part of a loosely coupled architecture, thus when deployed by itself, it might not provide all of its functionalities. Please refer to https://github.com/nuvlabox/deployment for a fully functional deployment

---

## Build the NuvlaBox Agent

This repository is already linked with Travis CI, so with every commit, a new NuvlaBox Agent Docker image is released. 

There is a [POM file](pom.xml) which is responsible for handling the multi-architecture and stage-specific builds.

**If you're developing and testing locally in your own machine**, simply run `docker build .` or even deploy the microservice via the local [compose files](docker-compose.localhost.yml) to have your changes built into a new Docker image, and saved into your local filesystem.

**If you're developing in a non-master branch**, please push your changes to the respective branch, and wait for Travis CI to finish the automated build. You'll find your Docker image in the [nuvladev](https://hub.docker.com/u/nuvladev) organization in Docker hub, names as _nuvladev/agent:\<branch\>_.

## Deploy the NuvlaBox Agent

The NuvlaBox agent will only work if a [Nuvla](https://github.com/nuvla/deployment) endpoint is provided and a NuvlaBox has been added in Nuvla.

### Prerequisites 

 - *Docker (version 18 or higher)*
 - *Docker Compose (version 1.23.2 or higher)*

### Environment variables

 - NUVLABOX_UUID - (**required**)before starting the NuvlaBox Agent, make sure you export the ID of the NuvlaBox you've created through Nuvla: `export NUVLABOX_UUID=<nuvlabox id from nuvla>`
 - NUVLA_ENDPOINT_INSECURE - if you're using an insecure Nuvla endpoint, set this to `True`: `export NUVLA_ENDPOINT_INSECURE=True`
 - NUVLA_ENDPOINT - if you're not using [nuvla.io](https://nuvla.io) then set this to your Nuvla endpoint: `export NUVLA_ENDPOINT=<your endpoint>`

### Launching the NuvlaBox Agent

Simply run `docker-compose up`

### If Nuvla is running on `localhost`

If Nuvla is running in the same machine, then you'll need to tweak the Docker network to allow the NuvlaBox Agent to reach out to Nuvla at localhost.

In this scenario, please follow the instructions from https://github.com/nuvlabox/deployment#test-deployment, and use the [docker-compose.localhost.yml](docker-compose.localhost.yml) file.


## Test the NuvlaBox Agent

This microservice is completely automated, meaning that as long as all the proper environment variables have been correctly set and the right dependencies have been met, the respective Docker container will start by itself, automatically activate the NuvlaBox in Nuvla and start sending telemetry to periodically.

## Contributing

This is an open-source project, so all community contributions are more than welcome. Please read [CONTRIBUTING.md](Contributing.md)
 
## Copyright

Copyright &copy; 2019, SixSq Sàrl
