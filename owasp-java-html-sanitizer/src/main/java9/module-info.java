// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

/**
 * The OWASP Java HTML Sanitizer: takes third-party HTML and produces HTML
 * that is safe to embed in your web application.
 *
 * <p>This descriptor is compiled for Java 9 and packaged under
 * {@code META-INF/versions/9/} in a multi-release jar, so the jar stays
 * usable on Java 8, which never looks there, while Java 9 and later read
 * it as an explicit module.  Only {@code org.owasp.html} is exported.
 * {@code org.owasp.shim}, the Java 8 shim bundled into this jar, is an
 * implementation detail and stays encapsulated.
 */
module owasp.java.html.sanitizer {
  exports org.owasp.html;

  // The JSR 305 nullability and concurrency annotations on the API
  // (javax.annotation and javax.annotation.concurrent) document it and have
  // no runtime behaviour, so the dependency is compile-time only and a
  // consumer need not have jsr305 on its module path.  The jsr305 jar has no
  // Automatic-Module-Name, so its module name derives from the file name.
  requires static jsr305;
}
