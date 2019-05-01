FROM python:3-slim

ARG GIT_BRANCH
ARG GIT_COMMIT_ID
ARG GIT_DIRTY
ARG GIT_BUILD_TIME
ARG TRAVIS_BUILD_NUMBER
ARG TRAVIS_BUILD_WEB_URL

LABEL git.branch=${GIT_BRANCH}
LABEL git.commit.id=${GIT_COMMIT_ID}
LABEL git.dirty=${GIT_DIRTY}
LABEL git.build.time=${GIT_BUILD_TIME}
LABEL travis.build.number=${TRAVIS_BUILD_NUMBER}
LABEL travis.build.web.url=${TRAVIS_BUILD_WEB_URL}

RUN apt update && apt install -y usbutils lsof procps

RUN apt-get clean autoclean
    && apt-get autoremove --yes
    && rm -rf /var/lib/{apt,dpkg,cache,log}/

COPY code/* /opt/nuvlabox/agent/

WORKDIR /opt/nuvlabox/agent/

RUN pip install -r requirements.txt

VOLUME /srv/nuvlabox/shared

CMD ["echo", " ### WIP ### $(whoami) "]