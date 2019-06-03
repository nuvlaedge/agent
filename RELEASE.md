## Release Process

Check that everything builds correctly with:

    mvn clean install

To tag the code with the release version and to update the master
branch to the next snapshot version, run the command:

    ./release.sh true [VERSION] [SKIP_CHANGELOG]

If you want to test what will happen with the release, leave off the
"true" argument and the changes will only be made locally.

If VERSION is blank, then the current version in `pom.xml` will be
used for the release.  If SKIP_CHANGELOG is not blank, then the
interactive generation of the CHANGELOG entry will be skipped.

When the tag is pushed to GitHub, Travis CI will build the repository,
create the container, and push it to Docker Hub.  Check the Travis
build and ensure that the new container versions appear in the Docker
Hub.
