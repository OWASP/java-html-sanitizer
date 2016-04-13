#!/bin/bash

set -e

# Invoked from .travis.yml to verify the build.

export COMMON_FLAGS="-Dgpg.skip=true -B -V"

if echo $TRAVIS_JDK_VERSION | egrep -q 'jdk[6789]'; then
    # Build the whole kit-n-kaboodle.
    exec mvn -f aggregate verify $COMMON_FLAGS
else
    # The main library only uses jdk5 compatible dependencies,
    # and the javadoc for java 5 doesn't barfs on the
    # -Xdoclint flags we use.
    exec mvn verify -Dmaven.javadoc.skip=true $COMMON_FLAGS
fi
