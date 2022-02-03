FROM python:3.7-slim-buster AS psutil-builder

RUN apt update && apt install -y gcc

WORKDIR /tmp

COPY code/requirements.base.txt .
RUN pip install -r requirements.base.txt

# ---

FROM python:3.7-slim-buster

ARG GIT_BRANCH
ARG GIT_COMMIT_ID
ARG GIT_BUILD_TIME
ARG GITHUB_RUN_NUMBER
ARG GITHUB_RUN_ID
ARG PROJECT_URL

LABEL git.branch=${GIT_BRANCH}
LABEL git.commit.id=${GIT_COMMIT_ID}
LABEL git.build.time=${GIT_BUILD_TIME}
LABEL git.run.number=${GITHUB_RUN_NUMBER}
LABEL git.run.id=${GITHUB_RUN_ID}
LABEL org.opencontainers.image.authors="support@sixsq.com"
LABEL org.opencontainers.image.created=${GIT_BUILD_TIME}
LABEL org.opencontainers.image.url=${PROJECT_URL}
LABEL org.opencontainers.image.vendor="SixSq SA"
LABEL org.opencontainers.image.title="NuvlaBox Agent"
LABEL org.opencontainers.image.description="Sends the NuvlaBox telemetry, hearbeat, and lifecycle management information to Nuvla"

COPY --from=psutil-builder /usr/local/lib/python3.7/site-packages /usr/local/lib/python3.7/site-packages

RUN apt update && apt install -y procps curl mosquitto-clients openssl

RUN set -eux; \
    Arch="$(dpkg --print-architecture)"; \
    case "$Arch" in \
      armv7|armhf) curl "https://project-downloads.drogon.net/wiringpi-latest.deb" --output /tmp/wiringpi.deb && dpkg -i /tmp/wiringpi.deb; \
    esac;

RUN apt-get clean autoclean \
    && apt-get autoremove --yes \
    && /bin/bash -c "rm -rf /var/lib/{apt,dpkg,cache,log}/"debian:stretch-slim

COPY code/ LICENSE /opt/nuvlabox/

WORKDIR /opt/nuvlabox/

RUN pip install -r requirements.txt

VOLUME /srv/nuvlabox/shared

ONBUILD RUN ./license.sh

ENTRYPOINT ["./app.py"]