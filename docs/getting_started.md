# Getting Started 

## Getting the JARs 

If you are using Maven then follow the [maven](maven.md) directions to
add a dependency.  Otherwise,
[download prebuilt jars](https://search.maven.org/#browse%7C-1545181754)
or `git clone git@github.com:OWASP/java-html-sanitizer.git` and build
the latest source.

Unless maven is managing your
[CLASSPATH](http://download.oracle.com//javase/1.3/docs/tooldocs/win32/classpath.html)
for you, you need to add both `owasp-java-html-sanitizer.jar` and the
Guava JAR.

Once you have your CLASSPATH set up correctly with the relevant JARs
you should be able to add

```Java
import org.owasp.html.HtmlPolicyBuilder;
```

to one of your project's `.java` files and compile it.

## Using the APIs 

The
[examples](https://github.com/OWASP/java-html-sanitizer/tree/master/src/main/org/owasp/html/examples)
include source code which defines a sanitization policy, and applies
it to HTML.

The
[javadoc](https://rawgit.com/OWASP/java-html-sanitizer/master/distrib/javadoc/index.html)
covers more detailed topics, including
[customization](https://rawgit.com/OWASP/java-html-sanitizer/master/distrib/javadoc/org/owasp/html/HtmlPolicyBuilder.html).

Important classes are:

  * [Sanitizers](https://rawgit.com/OWASP/java-html-sanitizer/master/distrib/javadoc/org/owasp/html/Sanitizers.html) contains combinable pre-packaged policies.
  * [HtmlPolicyBuilder](https://rawgit.com/OWASP/java-html-sanitizer/master/distrib/javadoc/org/owasp/html/HtmlPolicyBuilder.html) lets you easily build custom policies.

For advanced use, see:
  * [AttributePolicy](https://rawgit.com/OWASP/java-html-sanitizer/master/distrib/javadoc/org/owasp/html/AttributePolicy.html) and [ElementPolicy](https://rawgit.com/OWASP/java-html-sanitizer/master/distrib/javadoc/org/owasp/html/ElementPolicy.html) allow complex customization.
  * [HtmlStreamEventReceiver](https://rawgit.com/OWASP/java-html-sanitizer/master/distrib/javadoc/org/owasp/html/HtmlStreamEventReceiver.html) if you don't just want a `String` as output.

## Asking Questions 

Feel free to post questions at the
[discussion group](http://groups.google.com/group/owasp-java-html-sanitizer-support)
and we'll do our best to help.
