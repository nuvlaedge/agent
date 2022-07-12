ARG BASE_IMAGE
FROM  ${BASE_IMAGE:-python:3.8-alpine3.12} AS psutil-builder

RUN apk update && apk add --no-cache gcc musl-dev linux-headers

WORKDIR /tmp

COPY code/requirements.base.txt .
RUN pip install -r requirements.base.txt

# ---

FROM  ${BASE_IMAGE:-python:3.8-alpine3.12}

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

COPY --from=psutil-builder /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages

RUN apk update && apk add --no-cache procps curl mosquitto-clients openssl

COPY code/ LICENSE /opt/nuvlabox/

WORKDIR /opt/nuvlabox/

RUN pip install -r requirements.txt

VOLUME /srv/nuvlabox/shared

ONBUILD RUN ./license.sh

ENTRYPOINT ["./agent_main.py"]