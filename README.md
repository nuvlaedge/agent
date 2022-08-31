# NuvlaEdge Agent

[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg?style=for-the-badge)](https://github.com/nuvlaedge/agent/graphs/commit-activity)
[![GitHub issues](https://img.shields.io/github/issues/nuvlaedge/agent?style=for-the-badge&logo=github&logoColor=white)](https://GitHub.com/nuvlaedge/agent/issues/)
[![Docker pulls](https://img.shields.io/docker/pulls/nuvlaedge/agent?style=for-the-badge&logo=Docker&logoColor=white)](https://cloud.docker.com/u/nuvlaedge/repository/docker/nuvlaedge/agent)
[![Docker image size](https://img.shields.io/docker/image-size/nuvladev/agent/master?logo=docker&logoColor=white&style=for-the-badge)](https://cloud.docker.com/u/nuvlaedge/repository/docker/nuvlaedge/agent)

![CI Build](https://github.com/nuvlaedge/agent/actions/workflows/main.yml/badge.svg)
![CI Release](https://github.com/nuvlaedge/agent/actions/workflows/release.yml/badge.svg)


**This repository contains the source code for the NuvlaEdge Agent - the microservice which is responsible for the [NuvlaEdge](https://sixsq.com/products-and-services/nuvlaedge/overview) activation, categorization and telemetry.**

This microservice is an integral component of the NuvlaEdge Engine.

---

**NOTE:** this microservice is part of a loosely coupled architecture, thus when deployed by itself, it might not provide all of its functionalities. Please refer to https://github.com/nuvlaedge/deployment for a fully functional deployment

---

## Build the NuvlaEdge Agent

This repository is already linked with Travis CI, so with every commit, a new Docker image is released.

There is a [POM file](pom.xml) which is responsible for handling the multi-architecture and stage-specific builds.

**If you're developing and testing locally in your own machine**, simply run `docker build .` or even deploy the microservice via the local [compose files](docker-compose.yml) to have your changes built into a new Docker image, and saved into your local filesystem.

**If you're developing in a non-master branch**, please push your changes to the respective branch, and wait for Travis CI to finish the automated build. You'll find your Docker image in the [nuvladev](https://hub.docker.com/u/nuvladev) organization in Docker hub, names as _nuvladev/agent:\<branch\>_.

## Deploy the NuvlaEdge Agent

The NuvlaEdge agent will only work if a [Nuvla](https://github.com/nuvla/deployment) endpoint is provided and a NuvlaEdge has been added in Nuvla.

### Prerequisites

 - *Docker (version 18 or higher)*
 - *Docker Compose (version 1.23.2 or higher)*

### Environment variables

|                          	|                                                                                                                                                       	|
|-------------------------	|------------------------------------------------------------------------------------------------------------------------------------------------------	|
|           NUVLAEDGE_UUID 	| (**required**) before starting the NuvlaEdge Agent, make sure you export the ID of the NuvlaEdge you've created through Nuvla: `export NUVLAEDGE_UUID=<nuvlaedge id from nuvla>` 	|
| NUVLA_ENDPOINT_INSECURE 	| if you're using an insecure Nuvla endpoint, set this to `True`: `export NUVLA_ENDPOINT_INSECURE=True`                                                	|
|          NUVLA_ENDPOINT 	| if you're not using [nuvla.io](https://nuvla.io) then set this to your Nuvla endpoint: `export NUVLA_ENDPOINT=<your endpoint>`                                      	|
| | |

### Launching the NuvlaEdge Agent

Simply run `docker-compose up --build`

## Test the NuvlaEdge Agent

This microservice is completely automated, meaning that as long as all the proper environment variables have been correctly set and the right dependencies have been met, the respective Docker container will start by itself, automatically activate the NuvlaEdge in Nuvla and start sending telemetry to periodically.

### Agent API Calls

The NuvlaEdge Agent provides an internal REST API for allowing other NuvlaEdge component to interact with Nuvla without having to implement their own Nuvla API clients, thus reducing duplicated code throughout the NuvlaEdge software stack.

**The API is not published outside the Docker network, and is available at _http://agent/api_**

#### Get agent healthcheck

Returns something if the agent and respective API are already up and running. This call is meant to be used as a healthcheck for other components that are waiting for the agent to be ready.

 - **URL**

    /api/healthcheck

 - **Methods**

    `GET`

 - **URL Params**

    None

 - **On success**
    - Code: `200`

        Content: `True`

 - **Example**

    ```
    curl --fail -X GET http://agent/api/healthcheck
    ```   

#### Re-commission the NuvlaEdge

It might happen that due to a change in the NuvlaEdge or a need to refresh certain credentials and/or system configurations, the NuvlaEdge needs to be re-commissioned so that Nuvla can propagate the new changes. This call will trigger a NuvlaEdge re-commissioning, according to the request payload.

This call is tailored to be used by specific NuvlaEdge components like the Network Manager.


#### Manage NuvlaEdge peripherals

Gives other NuvlaEdge components the ability to register and manage NuvlaEdge peripherals in Nuvla.

##### Register a new NuvlaEdge peripheral

Creates a new nuvlabox-peripheral resource in Nuvla and save a local copy of this peripheral locally in the NuvlaEdge.


 - **URL**

    /api/peripheral

 - **Methods**

    `POST`

 - **URL Params**

    None

  - **Data payload**

    JSON document with a structure matching the `nuvlabox-peripheral` [resource in Nuvla](https://nuvla.io/ui/documentation/nuvlabox-peripheral-1-1)

 - **On success**
    - Code: `201`

        Content: JSON response from Nuvla. Example:

                ```
                {
                    "status": 201,
                    "message": "some message",
                    "resource-id": "<uuid of the Nuvla resource>"
                }
                ```

 - **On error**
    - Code: `400`

        Content: `{"error": "error message"}`

    - Code: `500`

        Content: `{"error": "error message"}`

    - Code: others

        Content: If the error has been thrown during the interaction with the Nuvla API, then the Nuvla response will be literally forwarded. This response might include error codes like `403`, `404`, `409`, etc.


 - **Example**

    ```
    curl --fail -X POST http://agent/api/peripheral \
            -H content-type:application/json \
            -d '''{
                    "available": true,
                    "classes": ["audio", "video"],
                    "name": "my peripheral",
                    "description": "description of my awesome peripheral",
                    "device-path": "/dev/mydevice",
                    "identifier": "unique-local-peripheral-id",
                    "interface": "USB",
                    "product": "Gadget A",
                    "serial-number": "1234567890",
                    "vendor": "company A"
                   }'''

    ```   

    Response:
    ```
    {
        "message":"nuvlabox-peripheral/d149dc67-fd5c-402d-8608-306852a8c0f3 created",
        "resource-id":"nuvlabox-peripheral/d149dc67-fd5c-402d-8608-306852a8c0f3",
        "status":201    
    }
    ```

##### Search for a NuvlaEdge peripheral

Returns a list of NuvlaEdge peripherals matching the URL params in the request.

 - **URL**

    /api/peripheral

 - **Methods**

    `GET`

 - **URL Params**

    `parameter=<peripheral-parameter-name>`

    `value=<peripheral-parameter-value>`

    `identifier_pattern=<pattern-for-multiple-peripheral-identifiers>`


  - **Data payload**

    None

 - **On success**
    - Code: `200`

        Content: Dict of matching peripheral identifiers

 - **Examples**

    ```
    curl --fail -X GET 'http://agent/api/peripheral?parameter=interface&value=USB'
    ```   

    Response:
    ```
    {"peripheral-identifier": {"interface": ...}}
    ```
    ---


    ```
    curl --fail -X GET 'http://agent/api/peripheral?parameter=interface&value=BT'
    ```   

    Response:
    ```
    {}
    ```

    ---


    ```
    curl --fail -X GET 'http://agent/api/peripheral?identifier_pattern=unique-local*'
    ```   

    Response:
    ```
    {"peripheral-1-id": {...}, "peripheral-2-id": {...}}
    ```


##### Manage an existing peripheral

Provides reading and editing capabilities for an existing peripheral.

 - **URL**

    /api/peripheral/<identifier>

 - **Methods**

    `DELETE`

 - **URL Params**

    None

  - **Data payload**

    None

 - **On success**
    - Code: `200`

        Content: `{"message": "successfully deleted ..."}` (can contain extra fields like `status` and `resource-id`)

 - **On error**
    - Code: `404`

        Content: `{"error": "not found error message"}`

    - Code: `500`

        Content: `{"error": "error message"}`

    - Code: others

        Content: If the error has been thrown during the interaction with the Nuvla API, then the Nuvla response will be literally forwarded. This response might include error codes like `403`, `404`, `409`, etc.


 - **Example**

    ```
    curl -X DELETE http://agent/api/peripheral/bad-local-peripheral
    ```   

    Response:
    ```
    {
        "error":"Peripheral not found"
    }
    ```



## Contributing

This is an open-source project, so all community contributions are more than welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)

## Copyright

Copyright &copy; 2021, SixSq SA
