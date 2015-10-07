# Code in Client-side template

Some substrings are specially interpreted by client-side template.  For example, `{{...}}` might contain an expression or binding in Angular JS or Polymer.

This document collects information about substrings that we need to defang to prevent a sanitized substring from being interpreted as high-privilege code by a client-side template.

## Client-side template substrings that appear in Text Nodes

Many client-side templates look for special constructs in text nodes.  Often, using character references (`&lbrace;`) will not affect interpretation since the client-side template is evaluated by JavaScript operating on the DOM after the HTML parser has decoded character references.

| Template Language | Construct | Example | Notes |
| ----------------- | --------- | ------- | ----- |
| Angular           | `{{`...`}}` | [`{{buttonText}}`](https://docs.angularjs.org/guide/templates) | 
| Polymer           | `{{`...`}}` | [`{{arrayOfFriends | startsWith('M')}}`](expressions) |
| CanJS             | `<%`...`%>` | [`<% alert(0) %>`] | |
| Underscore        | `<%`...`%>` | [`<% alert(0) %>`] | |
| Ember             | `{{`...`}}` | [`{{#view tagName=script}}alert(2){{/view}}`] | |
| Ractive           | `{{`...`}}` | [`{{#1..constructor.constructor('alert(1)')():num}}`] | |
| JsRenderer        | `{{`...`}}` | [`{{:constructor.constructor('alert(2)')()}}`] | |
| KendoUI           | `#`...`#`   | [`# alert(1) #`] | |

## Client side template / expression attributes

When filtering client-side templates, it should also be considered to fully cover attributes containing expressions and parseable information that might cause damage or lead to arbitary JavaScript execution.

| Template Language | Attrbutes | Notes |
|-------------------|-----------|-------|
| Angular           | `ng-xxx`, `ng:xxx`, `data-ng-xxx`, `x-ng-xxx`          | Angular normalizes attribute names before parsing their contents, making it impossible to work with blacklists. Further, Angular allows to e.g. fetch imports form within a class attribute. This means, we should also consider filtering contents.      |
| Vue               | `v-xxx`   |       |
| Knockout          | `data-xxx` |      |
| Ember             | `data-xxx` |      |


## Escaping of sensitive constructs

| Substring | Defangs | PCDATA Replacement | RCDATA Replacement† | Notes |
| --------- | ------- | ------------------ | ------------------- | ----- |
| `{` (`{` / *end-of-input*) | `{{`...`}}` | `{<!-- -->` | `{` U+200B | Comment breaks text nodes.  U+200B is a zero-width space and is not semantics preserving in RCDATA | 

† - RCDATA is the content type of `<title>` and `<textarea>` elements.  These often do not appear in sanitized text, but can be harder to defang.

TODO: do we need to consider `<![CDATA[...]]>` and foreign XML contexts.

TODO: what do client side templates do with comments in the DOM?

## Test-cases
