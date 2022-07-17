ARG BASE_IMAGE=python:3.8-alpine3.12
FROM ${BASE_IMAGE}

RUN apk --no-cache add iproute2

ENTRYPOINT ["ip"]
