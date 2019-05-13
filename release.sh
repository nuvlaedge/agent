#!/bin/bash -x

TAG_VERSION=NONE

VERSION=$2

PUSH_CHANGES=${1:-false}

BRANCH=master

if [ "${PUSH_CHANGES}" == "true" ]; then
    TARGET=deploy
else
    TARGET=install
fi

do_push() {
    if [ "${PUSH_CHANGES}" == "true" ]; then
        echo "INFO: PUSHING changes."
        git push
    else
        echo "INFO: not pushing changes."
    fi
}

do_push_tag() {
    if [ "${PUSH_CHANGES}" == "true" ]; then
        echo "INFO: PUSHING tag ${TAG_VERSION}."
        git push origin ${TAG_VERSION}
    else
        echo "INFO: not pushing tag."
    fi
}

# update pom.xml files for tag and next development version
tag_release() {

  # make the release tag
  (git add . ; git commit -m "release ${TAG_VERSION}"; do_push; git tag ${TAG_VERSION}; do_push_tag)

}

# update pom.xml files for tag and next development version
update_to_snapshot() {

  # update to next development version
  (git add . ; git commit -m "next development version"; do_push)
}

do_tag() {
    echo "TAGGING ${TAG_VERSION}"
    tag_release
    echo
}

do_update() {
    echo "UPDATING TO SNAPSHOT ${NEXT_RELEASE}"
    update_to_snapshot
    echo
}

update_pom_versions() {
    v=$1
    if [ "${v}" == "" ]; then
        echo "missing version for pom version update"
        exit 1
    fi

    mvn -Djvmargs="-Xmx1024M" \
        -f pom.xml \
        -B \
        -DskipTests \
        versions:set -DnewVersion=${v} -DgenerateBackupPoms=false
}

update_project_versions() {
    v=$1
    if [ "${v}" == "" ]; then
        echo "missing version for project.clj version update"
        exit 1
    fi
    echo 'Updating project.clj versions to ' ${v}
    find . -name project.clj -exec sed -i.bck "s/^(defproject sixsq.nuvla.server\/api-jar .*/(defproject sixsq.nuvla.server\/api-jar \"${v}\"/" {} \;
}

update_changelog() {
    changelog_file="CHANGELOG.md"
    text="$1"
    sed -i.bck "2i\\
$text
" ${changelog_file}
}

do_changelog() {
    changelog_ready="n"
    while [[ "${changelog_ready}" == "n" ]]
    do
        release_headline="## [${TAG_VERSION}] - $(date +%Y-%m-%d)"
        added='### Added'
        changed='### Changed'
        newline="placeholder"
        while true
        do
            read -p "added (empty line to stop writing): " newline
            if [[ -z $newline ]]
            then
                break
            else
                added="${added}\n  - ${newline}"
            fi
        done

        newline="placeholder"
        while true
        do
            read -p "changed (empty line to stop writing): " newline
            if [[ -z $newline ]]
            then
                break
            else
                changed="${changed}\n  - ${newline}"
            fi
        done

        full_changelog="${release_headline}\n${added}\n${changed}"
        printf "Your new CHANGELOG entry is:\n\n${full_changelog}\n\n"
        read -p "continue? (y/n): " changelog_ready
    done
    update_changelog "${full_changelog}"
}

cleanup() {
    rm versions.sh
    mvn clean
    git status
}


#
# automatically prepare the release version, if provided
#

if [[ ! -z $VERSION ]]
then
    echo "INFO: updating project version to ${VERSION} before releasing"
    if [[ "${VERSION}" != *"-SNAPSHOT" ]]
    then
        echo "ERR: new versions must include the SNAPSHOT suffix"
        exit 1
    fi
    update_pom_versions ${VERSION}
#    update_project_versions ${VERSION}
    echo "INFO: pushing the updated project version into GitHub"
    (git add . ; git commit -m "updating project to version ${VERSION}"; do_push)
    echo "WARN: please confirm that all builds are successfull before releasing..."
    exit 0
fi

#
# calculate the versions
#

mvn -Djvmargs="-Xmx1024M" \
    -f pom.xml \
    -B \
    -DskipTests \
    validate

source versions.sh

export TAG_VERSION
export NEXT_VERSION

echo ${TAG_VERSION}
echo ${NEXT_VERSION}


#
# add entries to CHANGELOG.md
#

do_changelog

#
# update to release version
#

update_pom_versions ${TAG_VERSION}
#update_project_versions ${TAG_VERSION}

#
# tag release
#

do_tag

#
# update to next snapshot version
#

update_pom_versions ${NEXT_VERSION}
#update_project_versions ${NEXT_VERSION}

#
# update master to snapshot
#
do_update

#
# cleanup
#

cleanup