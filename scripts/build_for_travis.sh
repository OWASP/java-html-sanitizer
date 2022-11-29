#!/bin/bash

set -e

# Invoked from .travis.yml to verify the build.

# Pass -Dgpg.skip to suppress signing instead of trying to provision
# Travis's containers with keys.
COMMON_FLAGS="-Dgpg.skip=true -B -V"

IS_LEGACY=""
if echo $TRAVIS_JDK_VERSION | egrep -q '(jdk|jre)[67]($|[^0-9])'; then
    IS_LEGACY=1
    # The main library only uses jdk6 compatible dependencies,
    # but Guava 21.0 is compatibility with jdk 7.
    COMMON_FLAGS="$COMMON_FLAGS -Dguava.version=20.0"
fi
if echo $TRAVIS_JDK_VERSION | egrep -q '(jdk|jre)([678]|11)($|[^0-9])'; then
    # Older versions of javadoc barf on -Xdoclint flags used
    # to configure the maven-javadoc-plugin.
    # JDK8 javadoc barfs on the flag "-html5]
    # JDK11 barfs too.  https://bugs.openjdk.java.net/browse/JDK-8212233
    # JDK9 is okay.  Yay!
    COMMON_FLAGS="$COMMON_FLAGS -Dmaven.javadoc.skip=true"
fi

echo "*** TRAVIS_JDK_VERSION=$TRAVIS_JDK_VERSION COMMON_FLAGS=($COMMON_FLAGS) IS_LEGACY=$IS_LEGACY"

mvn install -DskipTests=true $COMMON_FLAGS


if [ -n "$IS_LEGACY" ]; then
    # Don't bother building ancillary JARs and reports.
    exec mvn verify -Dmaven.javadoc.skip=true $COMMON_FLAGS
else
    # Build the whole kit-n-kaboodle.
    mvn                             -f aggregate/pom.xml       source:jar javadoc:jar verify $COMMON_FLAGS \
    && mvn -Dguava.version=27.1-jre -f aggregate/pom.xml clean source:jar javadoc:jar verify $COMMON_FLAGS \
    && mvn jacoco:report coveralls:report \
    && mvn org.sonatype.ossindex.maven:ossindex-maven-plugin:audit -f aggregate $COMMON_FLAGS
fi
