#!/bin/bash
set -e

echo Load html-containment.html?rerun into your browser then copy/paste the
echo JSON dump from the bottom into $PWD/canned-data.json

pushd ..
mvn install -DskipTests=true
popd

perl -i.bak -ne '
$found = 1 if m/^var cannedData = /;
print unless $found;' canned-data.js

python -c 'import json
import sys

json_dump = sys.stdin.read()
json_decoder = json.JSONDecoder()
canned_data, _ = json_decoder.raw_decode(json_dump)
print "var cannedData = %s;" % (
    json.dumps(canned_data, sort_keys=True, indent=2)
    .replace(", \n", ",\n"))' \
< canned-data.json \
>> canned-data.js

mvn package

mvn exec:java \
  -Dexec.mainClass=org.owasp.html.empiricism.JsonToSerializedHtmlElementTables \

cp html-metadata.ser ../src/main/resources/org/owasp/html
echo copied metadata to resources directory
