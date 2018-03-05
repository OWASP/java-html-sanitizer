#!/bin/bash

set -e

export VERSION="$1"

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <maven-version>"
    exit 1
fi

find docs README.md -name \*.md | \
    xargs perl -i~ -pe \
        's@\bhttps?://static[.]javadoc[.]io/com[.]googlecode[.]owasp-java-html-sanitizer/owasp-java-html-sanitizer/(?:[\w.\-]+)/(\w+)@https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/'"$VERSION"'/$1@'
