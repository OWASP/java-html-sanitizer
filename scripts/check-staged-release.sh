#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

# Checks that a release staging repository holds exactly the components a
# release publishes: the library and its parent under
# org.owasp.html-sanitizer, and a relocation POM at the coordinates used
# before issue #531.

set -euo pipefail

repository=${1:?staging repository required}
version=${2:?release version required}
if [[ ! $version =~ ^[0-9]{8}\.[0-9]+$ ]]; then
  echo 'Invalid release version' >&2
  exit 1
fi

library=org/owasp/html-sanitizer/html-sanitizer/$version/html-sanitizer-$version
parent=org/owasp/html-sanitizer/html-sanitizer-parent/$version/html-sanitizer-parent-$version
legacy=com/googlecode/owasp-java-html-sanitizer/owasp-java-html-sanitizer/$version/owasp-java-html-sanitizer-$version
expected=$(printf '%s\n' "$library.jar" "$library.pom" "$library-javadoc.jar" \
  "$library-sources.jar" "$parent.pom" "$legacy.pom" | sort)
# A checksum or signature counts as the file it belongs to, so one that sits
# beside no expected component is reported instead of being uploaded.  The
# repository metadata is the only thing JReleaser leaves out of the bundle.
actual=$(cd "$repository" && find . -type f ! -name 'maven-metadata.xml*' |
  sed -E 's#^\./##; s#(\.asc)?(\.(md5|sha1|sha256|sha512))?$##' | sort -u)
if [[ $actual != "$expected" ]]; then
  echo 'Staged artifacts differ from the expected release components:' >&2
  diff <(echo "$expected") <(echo "$actual") >&2 || true
  exit 1
fi
while IFS= read -r component; do
  if [[ ! -f $repository/$component ]]; then
    echo "Staged release lacks $component" >&2
    exit 1
  fi
done <<<"$expected"

relocation=$(tr -d ' \n\r\t' < "$repository/$legacy.pom")
for element in '<relocation><groupId>org.owasp.html-sanitizer</groupId><artifactId>html-sanitizer</artifactId>' \
               '<packaging>pom</packaging>'; do
  if [[ $relocation != *"$element"* ]]; then
    echo "Relocation POM lacks $element" >&2
    exit 1
  fi
done
target=${relocation#*<relocation>}
target=${target%%</relocation>*}
if [[ $relocation == *'<dependencies>'* || $target == *'<version>'* ]]; then
  echo 'Relocation POM must have no dependencies and no pinned target version' >&2
  exit 1
fi

# The library has no runtime dependencies and the shims are not published,
# so a dependency in its POM that is neither test nor provided scope would
# reach every consumer, and one on a shim would not resolve.
pom=$(tr -d ' \n\r\t' < "$repository/$library.pom")
if [[ $pom == *'<build>'* ]]; then
  pom=${pom%%<build>*}${pom##*</build>}
fi
dependencies=${pom#*<dependencies>}
dependencies=${dependencies%%</dependencies>*}
declared=$(grep -o '<dependency>' <<<"$dependencies" | wc -l | tr -d ' ')
scoped=$(grep -o -E '<scope>(test|provided)</scope>' <<<"$dependencies" | wc -l | tr -d ' ')
if [[ $pom != *'<dependencies>'* || $pom == *'<dependencyManagement>'* ||
      $declared -eq 0 || $declared -ne $scoped ]]; then
  echo "Library POM must declare only test and provided dependencies: $declared declared, $scoped so scoped" >&2
  exit 1
fi

entries=$(unzip -Z1 "$repository/$library.jar")
if ! grep -qx 'META-INF/maven/org.owasp.html-sanitizer/html-sanitizer/pom.properties' <<<"$entries"; then
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
