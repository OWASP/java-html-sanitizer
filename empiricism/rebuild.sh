#!/bin/bash
set -e
cd "$(dirname "$0")"

echo Load html-containment.html?rerun into your browser then copy/paste the
echo JSON dump from the bottom into $PWD/canned-data.json

pushd ..
./mvnw -ntp -B install -DskipTests
popd

# Regenerate the cannedData block into target/ first, so a bad paste into
# canned-data.json fails here without touching the tracked canned-data.js.
mkdir -p target
python3 -c 'import json
import sys

json_dump = sys.stdin.read()
json_decoder = json.JSONDecoder()
canned_data, _ = json_decoder.raw_decode(json_dump)
print("var cannedData = %s;" % (
    json.dumps(canned_data, sort_keys=True, indent=2)
    .replace(", \n", ",\n")))' \
< canned-data.json \
> target/canned-data-block.js

# Keep the header comment, replace everything from "var cannedData = " down.
perl -i~ -ne '
$found = 1 if m/^var cannedData = /;
print unless $found;' canned-data.js
cat target/canned-data-block.js >> canned-data.js

../mvnw -ntp -B package

../mvnw -ntp -B exec:java \
  -Dexec.mainClass=org.owasp.html.empiricism.JsonToSerializedHtmlElementTables

# TODO: Maybe do this via a genrule in the pom.xml
cp target/HtmlElementTablesCanned.java ../owasp-java-html-sanitizer/src/main/java/org/owasp/html
echo copied generated source to src directory
