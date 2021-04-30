FROM python:3-slim AS psutil-builder

RUN apt update && apt install -y gcc

WORKDIR /tmp

COPY code/requirements.base.txt .
RUN pip install -r requirements.base.txt

# ---

FROM python:3-slim

ARG GIT_BRANCH
ARG GIT_COMMIT_ID
ARG GIT_BUILD_TIME
ARG GITHUB_RUN_NUMBER
ARG GITHUB_RUN_ID

LABEL git.branch=${GIT_BRANCH}
LABEL git.commit.id=${GIT_COMMIT_ID}
LABEL git.build.time=${GIT_BUILD_TIME}
LABEL git.run.number=${GITHUB_RUN_NUMBER}
LABEL git.run.id=${TRAVIS_BUILD_WEB_URL}

COPY --from=psutil-builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages

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