# Code in Client-side template

Some substrings are specially interpreted by client-side template.  For example, `{{...}}` might contain an expression or binding in Angular JS or Polymer.

This document collects information about substrings that we need to defang to prevent a sanitized substring from being interpreted as high-privilege code by a client-side template.

## Client-side template substrings that appear in Text Nodes

Many client-side templates look for special constructs in text nodes.  Often, using character references (`&lbrace;`) will not affect interpretation since the client-side template is evaluated by JavaScript operating on the DOM after the HTML parser has decoded character references.

| Template Language | Construct | Example | Notes |
| ----------------- | --------- | ------- | ----- |
| Angular           | `{{`...`}}` | [`{{buttonText}}`](https://docs.angularjs.org/guide/templates) | 
| Polymer           | `{{`...`}}` | [`{{arrayOfFriends | startsWith('M')}}`](expressions) |

## Escaping of sensitive constructs

| Substring | Defangs | PCDATA Replacement | RCDATA Replacement† | Notes |
| --------- | ------- | ------------------ | ------------------- | ----- |
| `{` (`{` / *end-of-input*) | `{{`...`}}` | `{<!-- -->` | `{` U+200B | Comment breaks text nodes.  U+200B is a zero-width space and is not semantics preserving in RCDATA | 

† - RCDATA is the content type of `<title>` and `<textarea>` elements.  These often do not appear in sanitized text, but can be harder to defang.

TODO: do we need to consider `<![CDATA[...]]>` and foreign XML contexts.

TODO: what do client side templates do with comments in the DOM?

## Test-cases
