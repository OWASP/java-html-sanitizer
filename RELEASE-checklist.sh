#!/bin/bash

echo This is not meant to be run automatically.

exit

set -e


# Make sure the build is ok via
mvn -f aggregate clean verify site javadoc:jar source:jar

echo
echo Browse to
echo "file://$PWD/target/site"
echo and check the findbugs and jacoco reports.

echo
echo Check https://central.sonatype.org/pages/apache-maven.html#nexus-staging-maven-plugin-for-deployment-and-release
echo and make sure you have the relevant credentials in your ~/.m2/settings.xml

echo
echo Check https://search.maven.org/#search%7Cga%7C1%7Cowasp-java-html-sanitizer
echo and make sure that the current POM release number is max.

# Pick a release version
export DATE_STAMP="$(date +'%Y%m%d')"
export NEW_VERSION="$DATE_STAMP"".1"
export NEW_DEV_VERSION="$DATE_STAMP"".2-SNAPSHOT"
echo DATE_STAMP="$DATE_STAMP"
echo NEW_VERSION="$NEW_VERSION"
echo NEW_DEV_VERSION="$NEW_DEV_VERSION"

cd ~/work
export RELEASE_CLONE="$PWD/html-san-release"
rm -rf "$RELEASE_CLONE"
cd "$(dirname "$RELEASE_CLONE")"
git clone git@github.com:OWASP/java-html-sanitizer.git \
    "$(basename "$RELEASE_CLONE")"
cd "$RELEASE_CLONE"

# Update the version
# mvn release:update-versions puts -SNAPSHOT on the end no matter what
# so this is a two step process.
export VERSION_PLACEHOLDER=99999999999999-SNAPSHOT
for project in aggregate empiricism; do
    mvn -f $project \
        release:update-versions \
        -DautoVersionSubmodules=true \
        -DdevelopmentVersion="$VERSION_PLACEHOLDER"
done
find . -name pom.xml \
    | xargs perl -i.placeholder -pe "s/$VERSION_PLACEHOLDER/$NEW_VERSION/g"

# Make sure there's no snapshots left in any poms.
find . -name pom.xml | xargs grep -- -SNAPSHOT

# Make sure the change log is up-to-date.
perl -i.bak \
     -pe 'if (m/^  [*] / && !$added) { $_ = qq(  * Release $ENV{"NEW_VERSION"}\n$_); $added = 1; }' \
     change_log.md

$EDITOR change_log.md

# A dry run.
mvn -f aggregate clean source:jar javadoc:jar verify \
    -DperformRelease=true

# Commit and tag
git commit -am "Release candidate $NEW_VERSION"
git tag -m "Release $NEW_VERSION" -s "release-$NEW_VERSION"
git push origin "release-$NEW_VERSION"

# Actually deploy.
mvn -f aggregate clean source:jar javadoc:jar verify deploy:deploy \
    -DperformRelease=true

# Bump the development version.
for f in $(find . -name pom.xml.placeholder); do
    mv "$f" "$(dirname "$f")"/"$(basename "$f" .placeholder)"
done
find . -name pom.xml \
    | xargs perl -i -pe "s/$VERSION_PLACEHOLDER/$NEW_DEV_VERSION/"

git commit -am "Bumped dev version"

git push origin master

# Now Release
echo '1. Go to oss.sonatype.org'
echo '2. Look under staging repositories for one named'
echo '   comgooglecodeowasp-java-html-sanitizer-...'
echo '3. Close it.'
echo '4. Refresh until it is marked "Closed".'
echo '5. Check that its OK.'
echo '6. Release it.'
