#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

# Checks that a release staging repository holds exactly the components a
# release publishes: the library and its parent under org.owasp, and a
# relocation POM at the coordinates used before issue #531.

set -euo pipefail

repository=${1:?staging repository required}
version=${2:?release version required}
if [[ ! $version =~ ^[0-9]{8}\.[0-9]+$ ]]; then
  echo 'Invalid release version' >&2
  exit 1
fi

library=org/owasp/java-html-sanitizer/$version/java-html-sanitizer-$version
parent=org/owasp/java-html-sanitizer-parent/$version/java-html-sanitizer-parent-$version
legacy=com/googlecode/owasp-java-html-sanitizer/owasp-java-html-sanitizer/$version/owasp-java-html-sanitizer-$version
expected=$(printf '%s\n' "$library.jar" "$library.pom" "$library-javadoc.jar" \
  "$library-sources.jar" "$parent.pom" "$legacy.pom" | sort)
actual=$(cd "$repository" && find . -type f ! -name '*.md5' ! -name '*.sha1' \
  ! -name '*.sha256' ! -name '*.sha512' ! -name '*.asc' ! -name 'maven-metadata*' |
  sed 's#^\./##' | sort)
if [[ $actual != "$expected" ]]; then
  echo 'Staged artifacts differ from the expected release components:' >&2
  diff <(echo "$expected") <(echo "$actual") >&2 || true
  exit 1
fi

relocation=$(tr -d ' \n\r\t' < "$repository/$legacy.pom")
for element in '<relocation><groupId>org.owasp</groupId><artifactId>java-html-sanitizer</artifactId>' \
               '<packaging>pom</packaging>'; do
  if [[ $relocation != *"$element"* ]]; then
    echo "Relocation POM lacks $element" >&2
    exit 1
  fi
done
if [[ $relocation == *'<dependencies>'* || $relocation == *'<relocation><version>'* ]]; then
  echo 'Relocation POM must have no dependencies and no pinned target version' >&2
  exit 1
fi

entries=$(unzip -Z1 "$repository/$library.jar")
if ! grep -qx 'META-INF/maven/org.owasp/java-html-sanitizer/pom.properties' <<<"$entries"; then
  echo 'Library JAR lacks its own Maven metadata' >&2
  exit 1
fi
if grep -q '^META-INF/maven/.*shim' <<<"$entries"; then
  echo 'Library JAR carries shim Maven metadata' >&2
  exit 1
fi
if ! unzip -p "$repository/$library.jar" META-INF/MANIFEST.MF |
    grep -q '^Bundle-SymbolicName: com\.googlecode\.owasp-java-html-sanitizer'; then
  echo 'Library JAR has an unexpected OSGi symbolic name' >&2
  exit 1
fi
echo "Staged release $version has the expected components"
