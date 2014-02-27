#!/bin/bash

function requireLocalRepoUpToDate() {
  local LOCAL_CHANGES="$(svn status -u | egrep -v '^Status against revision:')"
  # -u causes status differences from head to be reported.
  if [[ -n "$LOCAL_CHANGES" ]]; then
      echo "Repo is not up-to-date or not committed."
      echo ========================================
      echo "$LOCAL_CHANGES"
      echo ========================================

      echo "Aborting."
      echo
      exit -1
  fi
}

requireLocalRepoUpToDate

PROJECT_DIR="$(pushd "$(dirname "$0")/../.." >& /dev/null; pwd -P; popd >& /dev/null)"

VERSION="$1"

PASSPHRASE="$2"

KEYNAME=41449802

function usageAndExit() {
  echo "Usage: $0 <version> <passphrase>"
  echo
  echo "Stages a release for deployment into Maven central"
  echo
  echo "<version> is the current SVN revision number."
  echo "svn info gives more info about the state of trunk."
  echo
  echo "<passphrase> is the passphrase for the GPG key $KEYNAME."
  echo "gpg --list-keys for more details on the key."
  echo
  echo "For example: $0 r123 ELIDED"
  exit -1
}

if ! [ -d "$PROJECT_DIR/maven" ]; then
  echo "Cannot determine script directory.  $PROJECT_DIR"
  usageAndExit
fi

if ! [[ "$VERSION" =~ r[0-9]+ ]]; then
  echo "Bad version $VERSION"
  echo
  usageAndExit
fi

if [ -z "$PASSPHRASE" ]; then
  echo "Missing passphrase"
  echo
  usageAndExit
fi

POMFILE="$PROJECT_DIR/maven/owasp-java-html-sanitizer/owasp-java-html-sanitizer/$VERSION/owasp-java-html-sanitizer-$VERSION.pom"

JAR_NO_EXT="$PROJECT_DIR/maven/owasp-java-html-sanitizer/owasp-java-html-sanitizer/$VERSION/owasp-java-html-sanitizer-$VERSION"

function requireFile() {
  local FILE="$1"
  if ! [ -e "$FILE" ]; then
      echo "Missing file : $FILE"
      echo
      usageAndExit
  fi
}

requireFile "$POMFILE"
requireFile "$JAR_NO_EXT".jar
requireFile "$JAR_NO_EXT"-sources.jar
requireFile "$JAR_NO_EXT"-javadoc.jar

mvn -X -e \
  gpg:sign-and-deploy-file \
  -Dgpg.keyname="$KEYNAME" \
  -Dgpg.passphrase="$PASSPHRASE" \
  -DgeneratePom=false \
  -DpomFile="$POMFILE" \
  -Dfile="$JAR_NO_EXT".jar \
  -Dfiles="$JAR_NO_EXT"-sources.jar,"$JAR_NO_EXT"-javadoc.jar \
  -Dtypes=jar,jar \
  -Dclassifiers=sources,javadoc \
  -Durl=https://oss.sonatype.org/service/local/staging/deploy/maven2/ \
  -DrepositoryId=sonatype-nexus-staging \
&& \
echo "Follow instructions at https://docs.sonatype.org/display/Repository/Sonatype+OSS+Maven+Repository+Usage+Guide#SonatypeOSSMavenRepositoryUsageGuide-8a.ReleaseIt"
