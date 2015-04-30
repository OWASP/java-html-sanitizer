# Attack Review Ground Rules 
### how our fail can be your win

Please take a look at [http://canyouxssthis.com/HTMLSanitizer](http://canyouxssthis.com/HTMLSanitizer).  That page includes a form that allows you to try out attacks against a sanitizer that implements the AntiSAMY [Ebay policy example](https://github.com/OWASP/java-html-sanitizer/tree/master/src/main/org/owasp/html/examples/EbayPolicyExample.java).

Enter an attack payload in that form, and it will be reflected back to you.  For example, if you enter `<b>Hello</b>, <i>World!</i>` you should see "**Hello**, _World!_" upon submitting the form.  If you want to see the actual HTML produced, just view source.

## How to win 
There are many ways we might have failed.

If you are the first to provide me with a payload that does any of the following on one of [Yahoo's A-list browsers](http://yuilibrary.com/yui/docs/tutorials/gbs/), then I will be happy to give credit via the project wiki and README, and I owe you a nice dinner next time we're in the same city (or coupon for dinner in your city).  Only the first reported payload that demonstrates a particular bug counts.

  * Pop up an `alert` with any text.
  * Cause a network load of `http://ha.ckers.org/xss.js` as JS
  * Set or retrieve `document.cookie`.
  * Cause the DOM to contain an element or attribute not explicitly allowed by the policy linked above (and not contained by `/reflect` with a blank input).
  * Cause an redirect to `http://ha.ckers.org/` or a URL of your choosing without user interaction.
  * Cause a save-file dialog to pop-up.
  * Crash the browser or cause it to loop infinitely until the browser halts JS or consume inordinate resources for an input of that size.
  * Cause an exception, crash, or inf. loop in the sanitizer that causes it to fail to provide service or consume inordinate resources for an input of that size.
  * Exfiltrate information from the page, such as the name or value of an input or the page title.
  * Exfiltrate keystrokes from the page.

This is not an exhaustive list and creative attacks are welcome.

If you find the web interface cumbersome, feel free to download and test the sanitizer directly.  See [GettingStarted](getting_started.md) for instructions.

## Reporting Vulnerabilities 
Please report successful attacks with example input via [the issue tracker](https://github.com/OWASP/java-html-sanitizer/issues/new).

If you believe the issue might affect production systems, please file the issue with the label `Private`.

If you wish to be credited, please provide a name or handle for me to credit.

If you wish to remain anonymous and still claim dinner at my expense, please file an issue with the label `Private` or send an email to `mikesamuel`@`gmail`.`com` and let me know how you will authenticate yourself should we meet.

## Out of Bounds 
We are testing the HTML sanitizer as written, not the servers on which the test framework runs, so hacking the server to change the code behind it or rewrite the HTML sanitizer is out of bounds.

## Questions 
Feel free to ask question in comments on this wiki page, or via the [project group](http://groups.google.com/group/owasp-java-html-sanitizer-support), or via my email address above.

I will also lurk on IRC `/join #owasp-html-sanitizer` using the handle `mikesamuel`.
