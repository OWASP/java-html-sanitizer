# Getting Started

## Getting the JARs

If you are using Maven then follow the [maven](maven.md) directions to
add a dependency.  Otherwise,
[download prebuilt jars](https://search.maven.org/artifact/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/)
or `git clone git@github.com:OWASP/java-html-sanitizer.git` and build
the latest source.

Unless maven is managing your CLASSPATH for you, you need to add `owasp-java-html-sanitizer.jar`.

Once you have your CLASSPATH set up correctly with the relevant JARs
you should be able to add

```Java
import org.owasp.html.HtmlPolicyBuilder;
```

to one of your project's `.java` files and compile it.

## Using the APIs

The
[examples](https://github.com/OWASP/java-html-sanitizer/tree/main/owasp-java-html-sanitizer/src/main/java/org/owasp/html/examples)
include source code which defines a sanitization policy, and applies
it to HTML.

The
[javadoc](http://javadoc.io/doc/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/)
covers more detailed topics, including
[customization](https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20240325.1/org/owasp/html/HtmlPolicyBuilder.html).

Important classes are:

  * [Sanitizers](https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20240325.1/org/owasp/html/Sanitizers.html) contains combinable pre-packaged policies.
  * [HtmlPolicyBuilder](https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20240325.1/org/owasp/html/HtmlPolicyBuilder.html) lets you easily build custom policies.

For advanced use, see:
  * [AttributePolicy](https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20240325.1/org/owasp/html/AttributePolicy.html) and [ElementPolicy](http://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20180219.1/org/owasp/html/ElementPolicy.html) allow complex customization.
  * [HtmlStreamEventReceiver](https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20240325.1/org/owasp/html/HtmlStreamEventReceiver.html) if you don't just want a `String` as output.

## Asking Questions

Feel free to post questions at the
[discussion group](http://groups.google.com/group/owasp-java-html-sanitizer-support)
and we'll do our best to help.
