// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

package org.owasp.html.java8check;

import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.owasp.html.Sanitizers;
import org.owasp.shim.Java8Shim;

/**
 * Checks, from the class path, that the packaged jar is usable by a consumer
 * that builds for or runs on Java 8.  See issue #515.
 *
 * <p>Java 8 builds commonly fail on any dependency that holds a class
 * compiled for a later release, with the Maven Enforcer rule
 * {@code enforceBytecodeVersion} at a {@code maxJdkVersion} of 1.8.  That
 * rule allows release N under {@code META-INF/versions/N/} of a
 * multi-release jar, where only Java N and later look, and nothing newer
 * than Java 8 anywhere else.  So this checks every class in the jar against
 * the same bound, then checks that the sanitizer picks the shim meant for
 * the runtime it is on, which is how a mistake in the versioned directory or
 * the {@code Multi-Release} manifest header would show.
 *
 * <p>The build runs this at the integration-test phase on the JDK running
 * the build, and CI also runs it on a Java 8 runtime, the one place the
 * Java 8 fallback shim is ever loaded.  Any failure exits non-zero.  It is
 * compiled for Java 8, so keep to Java 8 APIs here.
 */
public final class Java8ConsumerCheck {

  private Java8ConsumerCheck() {}

  /** A versioned entry of a multi-release jar, capturing its release. */
  private static final Pattern VERSIONED =
      Pattern.compile("^META-INF/versions/([0-9]+)/");

  /** Release N compiles to class file major version N + 44. */
  private static final int MAJOR_VERSION_OFFSET = 44;

  public static void main(String[] args) throws Exception {
    check(args.length == 1, "usage: Java8ConsumerCheck <packaged jar>");
    File jar = new File(args[0]).getCanonicalFile();

    // What a Java 8 build checks: nothing outside the versioned directories
    // is newer than Java 8, and nothing inside one is newer than its release.
    List<String> tooNew = new ArrayList<>();
    int classCount = 0;
    try (ZipFile zip = new ZipFile(jar)) {
      for (Enumeration<? extends ZipEntry> entries = zip.entries();
           entries.hasMoreElements();) {
        ZipEntry entry = entries.nextElement();
        String name = entry.getName();
        if (entry.isDirectory() || !name.endsWith(".class")) {
          continue;
        }
        ++classCount;
        Matcher versioned = VERSIONED.matcher(name);
        boolean isVersioned = versioned.find();
        int release = isVersioned ? Integer.parseInt(versioned.group(1)) : 8;
        int major = majorVersion(zip, entry);
        if (major > release + MAJOR_VERSION_OFFSET) {
          tooNew.add(name + " is compiled for Java "
              + (major - MAJOR_VERSION_OFFSET) + " but "
              + (isVersioned ? "sits in the directory for Java " + release
                 : "is outside META-INF/versions/"));
        }
      }
    }
    check(classCount != 0, "no classes in " + jar);
    check(tooNew.isEmpty(), "a Java 8 build rejects this jar: " + tooNew);

    // Java 10 and later read the versioned directory and find the shim that
    // uses their collection factories; Java 8 and 9 never see it and fall
    // back.
    int runtime = runtimeRelease();
    String expected = runtime >= 10
        ? "org.owasp.shim.ForJava10AndLater" : "org.owasp.shim.ForJava8";
    Class<?> shimClass = Java8Shim.j8().getClass();
    String shim = shimClass.getName();
    check(expected.equals(shim),
        "on Java " + runtime + " the sanitizer loaded " + shim
        + " rather than " + expected);

    // Those classes must come from the jar under test, not from a stray shim
    // or class directory earlier on the class path.
    for (Class<?> c : new Class<?>[] {
        Sanitizers.class, Java8Shim.class, shimClass }) {
      File source = new File(
          c.getProtectionDomain().getCodeSource().getLocation().toURI())
          .getCanonicalFile();
      check(jar.equals(source), c.getName() + " loaded from " + source);
    }

    String sanitized = Sanitizers.FORMATTING.sanitize(
        "<b onclick=\"steal()\">safe</b><script>alert(1)</script>");
    check("<b>safe</b>".equals(sanitized), "sanitized to " + sanitized);

    System.out.println(classCount + " classes in " + jar.getName()
        + " are within a Java 8 consumer's bounds; on Java " + runtime
        + " the sanitizer uses " + shim);
  }

  private static int majorVersion(ZipFile zip, ZipEntry entry)
      throws IOException {
    try (InputStream in = zip.getInputStream(entry)) {
      DataInputStream data = new DataInputStream(in);
      check(data.readInt() == 0xCAFEBABE, entry.getName() + " is not a class");
      data.readUnsignedShort();  // minor version
      return data.readUnsignedShort();
    }
  }

  /** 8 for "1.8", and the number itself from Java 9's "9" on. */
  private static int runtimeRelease() {
    String spec = System.getProperty("java.specification.version");
    return Integer.parseInt(spec.startsWith("1.") ? spec.substring(2) : spec);
  }

  private static void check(boolean condition, String failure) {
    if (!condition) {
      throw new AssertionError(failure);
    }
  }
}
