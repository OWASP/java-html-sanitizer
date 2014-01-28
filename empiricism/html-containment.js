var notify = [];
var experimentIdCounter = 0;
/**
 * The questions above are answered by running a bunch of experiments
 * exhaustively for all combinations of HTML element names.
 *
 * @param makeHtmlString takes one or more element names.
 *    Its {@code length} property specifies its arity, and runExperiment
 *    calls it iteratively with every permutation of length element names.
 * @param checkDom receives the element names passed to makeHtmlString,
 *    an HTML document body created by parsing the HTML from makeHtmlString
 *    and initialResult/return value from last call to checkDom.
 * @param initialResult the first result value to pass to checkDom.
 * @param opt_elementNames an array of element names which defaults to
 *    window.elementNames.
 */
function runExperiment(makeHtmlString, checkDom, initialResult, onResult,
                       opt_elementNames) {
  var experimentIndex = ++experimentIdCounter;
  var iframes = document.getElementById('experiment-iframes');
  var iframe = document.createElement('iframe');
  iframes.appendChild(iframe);

  var elementNames = opt_elementNames || window.elementNames;

  var nElements = elementNames.length;
  var arity = makeHtmlString.length;
  var nRuns = Math.pow(nElements, arity);
  var runIndex = 0;
  var paramIndices = new Array(arity);
  var paramValues  = new Array(arity);
  for (var i = 0; i < arity; ++i) {
    paramIndices[i] = 0;
    paramValues[i] = elementNames[0];
  }
  var exhausted = nRuns === 0;

  var progressCounterContainer =
    document.getElementById('experiment-progress-counter');

  var startTime = Date.now();
  var lastProgressUpdateTime = startTime;

  var result = initialResult;

  var progressCounter;
  if (progressCounterContainer) {
    progressCounter = document.createElement('li');
    progressCounter.style.width = '0';
    progressCounterContainer.appendChild(progressCounter);
  }

  function advance() {
    // Advance to next permutation.
    var i;
    for (i = arity; --i >= 0;) {
      if (++paramIndices[i] < nElements) {
        paramValues[i] = elementNames[paramIndices[i]];
        break;
      }
      paramIndices[i] = 0;
      paramValues [i] = elementNames[0];
    }
    ++runIndex;
    if (progressCounter) {
      var now = Date.now();
      if (now - lastProgressUpdateTime > 250 ) {
        var ratio = runIndex / nRuns;
        progressCounter.style.width = (100 * ratio).toFixed(2) + '%';
        lastProgressUpdateTime = now;
        var timeSoFar = now - startTime;
        if (timeSoFar > 5000) {
          // Assuming time per run is constant:
          // total_time / nRuns = time_so_far / runIndex
          // total_time = time_so_far * nRuns / runIndex
          //            = time_so_far / ratio
          // eta = total_time - time_so_far
          //     = time_so_far / ratio - time_so_far
          //     = time_so_far * (1/ratio - 1)
          var eta = timeSoFar * (1 / ratio - 1);
          progressCounter.innerHTML = eta > 250
              ? 'ETA:' + (eta / 1000).toFixed(1) + 's' : '';
        }
      }
    }
    exhausted = i < 0;
  }

  function step() {
    var htmlString = null;
    // Try to generate an HTML string.
    // The maker can return a nullish value to abort or punt on an experiment,
    // so we loop until we find work to do.
    while (!exhausted) {
      paramValues.length = arity;
      htmlString = makeHtmlString.apply(null, paramValues);
      if (htmlString != null) {
        break;
      }
      advance();
    }

    if (htmlString == null) { 
      var endTime = Date.now();
      console.log('experiment took %d millis for %d runs',
                  (endTime - startTime), nRuns);
      if (progressCounter) {
        setTimeout(function () {
          iframes.removeChild(iframe);
          progressCounterContainer.removeChild(progressCounter);
        }, 250);
      }
      onResult(result);
    } else {
      var notifyIndex = notify.indexOf(void 0);
      if (notifyIndex < 0) { notifyIndex = notify.length; }
      notify[notifyIndex] = function () {
        notify[notifyIndex] = void 0;

        // Process result
        paramValues[arity] = iframe.contentDocument.body;
        paramValues[arity + 1] = result;
        result = checkDom.apply(null, paramValues);
        paramValues.length = arity;

        // Requeue the next step on the parent frames event queue.
        setTimeout(function () { advance(); step(); }, 0);
      };
      // Start the iframe parsing its body.
      iframe.srcdoc = (
        '<!doctype html><html><head></head>'
        + '<body onload="parent.notify[' + notifyIndex + ']()">'
        + htmlString
      );
    }
  }
  step();
}

function formatDataToJsonHTML(data) {
  var out = [];
  var htmlForNullValue = '<span class="json-kw">null</span>';
  var htmlForErrorValue = '<span class="json-kw json-err">null</span>';
  var depth = 0;
  var spaces = '                ';
  format(data);
  return out.join('');

  function format(v) {
    if (v == null) {
      out.push(htmlForNullValue);
      return;
    }
    var t = typeof v;
    if (t === 'boolean') {
      out.push('<span class="json-kw">', v, '</span>');
    } else if (t === 'number') {
      if (isFinite(v)) {
        out.push('<span class="json-val">', v, '</span>');
      } else {
        out.push(htmlForErrorValue);
      }
    } else if (t === 'string' || v instanceof String) {
      var token = JSON.stringify(String(v));
      token = token.replace(/&/g, '&amp;').replace(/</g, '&lt;');
      out.push('<span class="json-str">', token, '</span>');
    } else {
      var length = v.length;
      var isSeries = ('number' === typeof length
                      && length === (length & 0x7fffffff));
      // Don't put properties on their own line if there are only a few.
      var inlinePropLimit = isSeries ? 8 : 4;
      var inline = true;
      var numProps = 0;
      for (var k in v) {
        if (!Object.hasOwnProperty.call(v, k)) { continue; }
        var propValue = v[k];
        if ((propValue != null && typeof propValue == 'object')
            || ++numProps > inlinePropLimit) {
          inline = false;
          break;
        }
      }
      // Put the appropriate white-space inside brackets and after commas.
      function maybeIndent(afterComma) {
        if (inline) {
          if (afterComma) { out.push(' '); }
        } else {
          out.push('\n');
          var nSpaces = depth * 2;
          while (nSpaces > 0) {
            var nToPush = Math.min(nSpaces, spaces.length);
            out.push(spaces.substring(0, nToPush));
            nSpaces -= nToPush;
          }
        }
      }
      var onclick = depth
        ? ' onclick="return toggleJsonBlock(this, event)"'
        : '';
      // Mark blocks so that we can do expandos on collections.
      out.push('<span class="json-ext json-block-', depth,
               depth === 0 || inline ? ' json-nocollapse' : '',
               '"', onclick, '>',
               isSeries ? '[' : '{',
               // Emit link-like ellipses that can serve as a button for
               // expando-ness.
               '<span class="json-ell">&hellip;</span>',
               '<span class="json-int">');
      ++depth;
      if (isSeries) {
        for (var i = 0; i < length; ++i) {
          if (i) { out.push(','); }
          maybeIndent(i !== 0);
          format(v[i]);
        }
      } else {
        var needsComma = false;
        for (var k in v) {
          if (!Object.hasOwnProperty.call(v, k)) { continue; }
          if (needsComma) {
            out.push(',');
          }
          maybeIndent(needsComma);
          out.push('<span class="json-prop">');
          format(String(k));
          out.push(': ');
          format(v[k]);
          out.push('</span>');
          needsComma = true;
        }
      }
      --depth;
      maybeIndent(false);
      out.push('</span>', isSeries ? ']' : '}', '</span>');
    }
  }
}

function displayJson(data, container) {
  container.innerHTML = formatDataToJsonHTML(data);
}

function toggleJsonBlock(el, event) {
  event && event.stopPropagation && event.stopPropagation();
  var className = el.className;
  var classNameCollapsed = className.replace(/\bjson-expanded\b/g, '');
  className = className === classNameCollapsed
      ? className + ' json-expanded' : classNameCollapsed;
  className = className.replace(/^ +| +$| +( [^ ])/g, "$1");
  el.className = className;
  return false;
}

function Promise() {
  if (!(this instanceof Promise)) { return new Promise(); }
  this.paused = [];
  this.satisfy = function () {
    var paused = this.paused;
console.log('satisfying ' + paused.length);
    for (var i = 0, n = paused.length; i < n; ++i) {
      setTimeout(paused[i], 0);
    }
    this.paused.length = 0;
  };
}
Promise.prototype.toString = function () { return "Promise"; };
function when(f, var_args) {
  var unsatisfied = [];
  for (var i = 1, n = arguments.length; i < n; ++i) {
    var argument = arguments[i];
    if (argument instanceof Promise) {
      unsatisfied.push(argument);
    }
  }
  var nToWaitFor = unsatisfied.length;
  if (nToWaitFor) {
    var pauser = function pauser() {
      if (!--nToWaitFor) {
        setTimeout(f, 0);
      }
    };
    for (var j = 0; j < nToWaitFor; ++j) {
      unsatisfied[j].paused.push(pauser);
    }
    unsatisfied = null;
  } else {
    setTimeout(f, 0);
  }
}

function newBlankObject() {
  return (Object.create || Object)(null);
}

function getOwn(o, k, opt_default) {
  return Object.hasOwnProperty.call(o, k) ? o[k] : opt_default;
}

function breadthFirstSearch(start, isEnd, eq, adjacent) {
  var stack = [{ node: start, next: null }];
  while (stack.length) {
    var candidate = stack.shift();
    if (isEnd(candidate.node)) {
      var path = [candidate.node];
      while (candidate.next) {
        candidate = candidate.next;
        path.push(candidate.node);
      }
      return path;
    }
    var adjacentNodes = adjacent(candidate.node);
    adj:
    for (var i = 0, n = adjacentNodes.length; i < n; ++i) {
      var adjacentNode = adjacentNodes[i];
      for (var dupe = candidate; dupe; dupe = dupe.next) {
        if (eq(dupe.node, adjacentNode)) { continue adj; }
      }
      stack.push({ node: adjacentNode, next: candidate });
    }
  }
  return null;
}

function reverseMultiMap(multimap) {
  var reverse = newBlankObject();
  for (var k in multimap) {
    if (Object.hasOwnProperty.call(multimap, k)) {
      var values = multimap[k];
      for (var i = 0, n = values.length; i < n; ++i) {
        var value = values[i];
        var reverseKeys = getOwn(reverse, value) || [];
        reverse[value] = reverseKeys;
        reverseKeys.push(k);
      }
    }
  }
  return reverse;
}

function innerTextOf(element) {
  function appendTextOf(node, out) {
    switch (node.nodeType) {
      case 1:  // Element
        for (var c = node.firstChild; c; c = c.nextSibling) {
          appendTextOf(c, out);
        }
        break;
      case 3: case 4: case 6:  // Text / CDATA / Entity
        out.push(node.nodeValue);
        break;
    }
  }
  var buf = [];
  if (element) { appendTextOf(element, buf); }
  return buf.join('');
}

function sortedMultiMap(mm) {
  var props = [];
  for (var k in mm) {
    if (!Object.hasOwnProperty.call(mm, k)) { continue; }
    var v = mm[k];
    if (v instanceof Array) {
      v = v.slice();
      v.sort();
    }
    props.push([k, v]);
  }
  props.sort(
      function (a, b) {
        a = a[0];
        b = b[0];
        if (a < b) { return -1; }
        if (b < a) { return 1; }
        return 0;
      });
  var sorted = newBlankObject();
  for (var i = 0, n = props.length; i < n; ++i) {
    var prop = props[i];
    sorted[prop[0]] = prop[1];
  }
  return sorted;
}

function makeSet(strs) {
  var s = newBlankObject();
  for (var i = 0, n = strs.length; i < n; ++i) {
    s[strs[i]] = s;
  }
  return s;
}

function inSet(s, str) {
  return s[str] === s;
}

function elementContainsComment(el) {
  return elementContainsNodeOfType(el, 8);
}

function elementContainsText(el) {
  return elementContainsNodeOfType(el, 3);
}

function elementContainsNodeOfType(el, nodeType) {
  if (el) {
    for (var c = el.firstChild; c; c = c.nextSibling) {
      if (c.nodeType === nodeType) { return true; }
    }
    return false;
  }
}
