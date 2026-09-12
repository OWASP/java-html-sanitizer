<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Browser Parser Experiments

This module measures how browsers nest and balance HTML tags.  It converts
those observations into the element tables used by the sanitizer.

This is an internal maintenance tool.  It is part of the Maven reactor so its
generator is compiled and checked, but it is not published.

## Files and data flow

1. [html-containment.html](html-containment.html) and
   [html-containment.js](html-containment.js) probe a browser's parser.
2. The probe emits JSON that is saved as [canned-data.json](canned-data.json).
3. [rebuild.sh](rebuild.sh) parses and formats that JSON into
   [canned-data.js](canned-data.js), then runs the
   [Java generator](src/main/java/org/owasp/html/empiricism/JsonToSerializedHtmlElementTables.java).
4. The generator writes `target/HtmlElementTablesCanned.java`, and the script
   copies it into the library as
   [HtmlElementTablesCanned.java](../owasp-java-html-sanitizer/src/main/java/org/owasp/html/HtmlElementTablesCanned.java).

`canned-data.json`, `canned-data.js`, and `HtmlElementTablesCanned.java` are
different representations of the same browser observations.  Never hand-edit
`HtmlElementTablesCanned.java`.

## Regenerating the tables

You need a browser with JavaScript enabled, Bash, Python 3, Perl, and
[JDK 11 or newer](../README.md#repository-layout).  The script uses the
repository's Maven wrapper.

1. Open the local `empiricism/html-containment.html` file in your browser and
   follow its `?rerun` link.  The full probe can take a long time; wait for it
   to finish.  Without `?rerun`, the page displays the saved observations.
2. Copy the complete JSON dump at the bottom of the page into
   `canned-data.json`.  Record the browser version used when describing the
   change.
3. From the repository root, run:

   ```sh
   ./empiricism/rebuild.sh
   ```

4. Review the diffs in `canned-data.json`, `canned-data.js`, and the generated
   Java file.  Explain changes in browser observations and add corresponding
   sanitizer tests where behavior changes.
5. Run the complete reactor before proposing the update:

   ```sh
   ./mvnw clean verify
   ```

For a quick diagnostic run, use `?rerun&shortlist`.  Its output covers only a
subset of elements; do not use it to replace the complete `canned-data.json`.

The rebuild script first installs the reactor artifacts into your local Maven
repository with tests skipped, then generates and copies the new tables.  The
final `clean verify` above compiles and tests the updated library.  A normal
Maven build uses the checked-in tables and does not run browser experiments.

Because these tables affect parsing and balancing of attacker-controlled HTML,
treat every data change as security-sensitive.  Include adversarial cases for
raw-text elements, misnested tags, foreign SVG and MathML content, case
differences, and serialize/reparse mutation where relevant.
