<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Browser Parser Experiments

HTML tag balancing has enough browser-specific behavior that this module
measures real browser parsers instead of deriving every rule from the HTML
specification.  The recorded observations are converted into the tables used
by the sanitizer.

This is an internal maintenance tool.  It is part of the Maven reactor so its
generator is compiled and checked, but it is not published.

## Files and data flow

1. `html-containment.html` and `html-containment.js` probe a browser's parser.
2. The probe emits JSON that is saved as `canned-data.json`.
3. `rebuild.sh` validates and formats that JSON into `canned-data.js`, then
   runs `JsonToSerializedHtmlElementTables`.
4. The generator writes `target/HtmlElementTablesCanned.java`, and the script
   copies it to
   `../owasp-java-html-sanitizer/src/main/java/org/owasp/html/`.

`canned-data.json`, `canned-data.js`, and `HtmlElementTablesCanned.java` are
different representations of the same browser observations.  Never hand-edit
`HtmlElementTablesCanned.java`.

## Regenerating the tables

You need a current mainstream browser, Python 3, Perl, and the same JDK and
Maven prerequisites as the main build.

1. Open `html-containment.html?rerun` in the browser.  The `?shortlist` option
   is useful for a quicker diagnostic run, but it is not the complete data set.
2. Copy the JSON dump shown at the bottom of the page into
   `canned-data.json`.
3. From the repository root, run:

   ```sh
   ./empiricism/rebuild.sh
   ```

4. Review all resulting diffs.  Changes in browser observations should have a
   clear explanation and corresponding sanitizer tests where behavior changes.
5. Run the complete reactor before proposing the update:

   ```sh
   ./mvnw clean verify
   ```

Because these tables affect parsing and balancing of attacker-controlled HTML,
treat every data change as security-sensitive.  Include adversarial cases for
raw-text elements, misnested tags, foreign SVG and MathML content, case
differences, and serialize/reparse mutation where relevant.
