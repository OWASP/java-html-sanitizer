# Code in Client-side template

Some substrings are specially interpreted by client-side template.  For example, `{{...}}` might contain an expression or binding in Angular JS or Polymer.

This document collects information about substrings that we need to defang to prevent a sanitized substring from being interpreted as high-privilege code by a client-side template.

## Client-side template substrings that appear in Text Nodes

Many client-side templates look for special constructs in text nodes.  Often, using character references (`&lbrace;`) will not affect interpretation since the client-side template is evaluated by JavaScript operating on the DOM after the HTML parser has decoded character references.

| Template Language | Construct | Example | Notes |
| ----------------- | --------- | ------- | ----- |
| Angular           | `{{`...`}}` | [`{{buttonText}}`](https://docs.angularjs.org/guide/templates) | 
| Polymer           | `{{`...`}}` | [`{{arrayOfFriends | startsWith('M')}}`](https://www.polymer-project.org/0.5/docs/polymer/expressions.html) |
| CanJS             | `<%`...`%>` | `<% alert(1) %>` | |
| Underscore        | `<%`...`%>` | `<% alert(1) %>` | |
| Ember             | `{{`...`}}` | `{{#view tagName=script}}alert(2){{/view}}` | |
| Ractive           | `{{`...`}}` | `{{#1..constructor.constructor('alert(1)')():num}}` | |
| JsRenderer        | `{{`...`}}` | `{{:constructor.constructor('alert(2)')()}}` | |
| KendoUI           | `#`...`#`   | `# alert(1) #` | |
| Vanilla ES6       | `` `${``...``}` ``  | `` `${alert(1)}` `` | | 

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

Current snapshot of DOMPurify test-cases (to be updated, please feel free to reorganize):

```javascript
assert.equal( DOMPurify.sanitize( '<a>123{{456}}<b><style><% alert(1) %></style>456</b></a>', {SAFE_FOR_TEMPLATES: true}), "<a> <b><style> </style>456</b></a>" );
assert.equal( DOMPurify.sanitize( '<a data-bind="style: alert(1)"></a>', {SAFE_FOR_TEMPLATES: true}), "<a></a>" );
assert.equal( DOMPurify.sanitize( '<a data-harmless=""></a>', {SAFE_FOR_TEMPLATES: true, ALLOW_DATA_ATTR: true}), "<a></a>" );
assert.equal( DOMPurify.sanitize( '<a data-harmless=""></a>', {SAFE_FOR_TEMPLATES: false, ALLOW_DATA_ATTR: false}), "<a></a>" );
assert.equal( DOMPurify.sanitize( '<a>{{123}}{{456}}<b><style><% alert(1) %><% 123 %></style>456</b></a>', {SAFE_FOR_TEMPLATES: true}), "<a> <b><style> </style>456</b></a>" );
assert.equal( DOMPurify.sanitize( '<a>{{123}}abc{{456}}<b><style><% alert(1) %>def<% 123 %></style>456</b></a>', {SAFE_FOR_TEMPLATES: true}), "<a> <b><style> </style>456</b></a>" );
assert.equal( DOMPurify.sanitize( '<a>123{{45{{6}}<b><style><% alert(1)%> %></style>456</b></a>', {SAFE_FOR_TEMPLATES: true}), "<a> <b><style> </style>456</b></a>" );
assert.equal( DOMPurify.sanitize( '<a>123{{45}}6}}<b><style><% <%alert(1) %></style>456</b></a>', {SAFE_FOR_TEMPLATES: true}), "<a> <b><style> </style>456</b></a>" );
assert.equal( DOMPurify.sanitize( '<a>123{{<b>456}}</b><style><% alert(1) %></style>456</a>', {SAFE_FOR_TEMPLATES: true}), "<a>123 <b> </b><style> </style>456</a>" );
assert.equal( DOMPurify.sanitize( '<b>{{evil<script>alert(1)</script><form><img src=x name=textContent></form>}}</b>', {SAFE_FOR_TEMPLATES: true}), "<b>  </b>" );
assert.equal( DOMPurify.sanitize( '<b>he{{evil<script>alert(1)</script><form><img src=x name=textContent></form>}}ya</b>', {SAFE_FOR_TEMPLATES: true}), "<b>he  ya</b>" );
```
