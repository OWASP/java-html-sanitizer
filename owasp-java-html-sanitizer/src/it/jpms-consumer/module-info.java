// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

/**
 * A consumer of the sanitizer on the module path.  The build compiles this
 * module against the packaged jar and runs it, so a jar that Java 9 and
 * later would not read as the explicit module {@code owasp.java.html.sanitizer}
 * fails right here with "module not found".  See issue #389.
 */
module org.owasp.html.jpmscheck {
  requires owasp.java.html.sanitizer;
}
