#!/bin/bash

function help_and_exit() {
    echo "Usage: $0 [-go] [-verbose] [-force]"
    echo
    echo "Moves minified CSS and JS to distribution directories and"
    echo "creates a branch in SVN."
    echo
    echo "  -go:       Run commands instead of just echoing them."
    echo "  -verbose:  More verbose logging."
    echo "  -force:    Ignore sanity checks for testing."
    echo "             Incompatible with -go."
    echo "  -nobranch: Don't create a new release branch."
    exit "$1"
}

# 1 for verbose logging
export VERBOSE="0"
# 1 if commands that have side-effects should actually be run instead of logged
export EFFECT="0"

for var in "$@"; do
  case "$var" in
      -verbose)
          VERBOSE="1"
          ;;
      -go)
          EFFECT="1"
          ;;
      -h)
          help_and_exit 0
          ;;
      *)
          echo "Unrecognized argument $var"
          help_and_exit -1
          ;;
  esac
done


function panic() {
    echo "PANIC: $*"

    if ! (( $NO_PANIC )); then
        exit -1
    fi
}

function command() {
    if (( $VERBOSE )) || ! (( $EFFECT )); then
        echo '$' "$*"
    fi
    if (( $EFFECT )); then
        "$@" || panic "command failed: $@"
    fi
}

export VERSION_BASE="$(
  pushd "$(dirname "$0")/../.." > /dev/null; pwd; popd > /dev/null)"

if ! [ -d "$VERSION_BASE/trunk/tools" ]; then
    panic "missing trunk/tools in $VERSION_BASE"
fi

VERSION="$(svn info | perl -ne 'print $1 if m/^Revision: (\d+)$/')"

DOWNLOADS_ZIP="$VERSION_BASE/trunk/out/owasp-java-html-sanitizer.zip"
VERSIONED_ZIP="$VERSION_BASE/trunk/out/owasp-java-html-sanitizer-r$VERSION.zip"

pushd "$VERSION_BASE/trunk" > /dev/null
command make download
popd > /dev/null

if ! [ -f "$DOWNLOADS_ZIP" ]; then
    panic "$DOWNLOADS_ZIP is not up-to-date"
fi

command cp "$DOWNLOADS_ZIP" "$VERSIONED_ZIP"

command "$VERSION_BASE/trunk/tools/googlecode_upload.py" \
    --summary="JARs, source JAR, and documentation for version $VERSION." \
    -p owasp-java-html-sanitizer -u mikesamuel \
    --labels='Type-Archive,OpSys-All,Featured' \
    "$VERSIONED_ZIP"

if (( $EFFECT )); then
    echo "Don't forget to mark any old ones deprecated at"
    echo "https://code.google.com/p/owasp-java-html-sanitizer/downloads/list"
else
    echo
    echo "Rerun with -go to actually run these commands."
fi
