// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

package org.owasp.html.jpmscheck;

import java.lang.module.ModuleDescriptor;
import java.lang.module.ModuleDescriptor.Exports;
import java.lang.module.ModuleDescriptor.Requires;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

/**
 * Checks, from inside a named module that requires the sanitizer, that the
 * packaged jar is the explicit JPMS module issue #389 asked for.
 *
 * <p>The build runs this at the integration-test phase with the packaged
 * jar and this module on the module path and nothing else, which is how a
 * consumer that declares {@code requires owasp.java.html.sanitizer} sees
 * the library.  Any failure exits non-zero and fails the build.  This is not
 * a unit test: the sanitizer's tests are compiled for Java 8 and cannot
 * name {@link java.lang.Module}, and they run before the jar exists.  It is
 * compiled for Java 9, the release the descriptor targets, so keep to Java 9
 * APIs here.
 */
public final class JpmsConsumerCheck {

  private JpmsConsumerCheck() {}

  public static void main(String[] args) {
    Module module = PolicyFactory.class.getModule();
    check(module.isNamed(), "the sanitizer is in the unnamed module");
    check("owasp.java.html.sanitizer".equals(module.getName()),
        "unexpected module name " + module.getName());

    ModuleDescriptor descriptor = module.getDescriptor();
    check(!descriptor.isAutomatic(),
        "the sanitizer was resolved as an automatic module, so the jar's"
        + " module-info.class was not read");
    check(!descriptor.isOpen(), "the module is open");

    // The API package, and nothing else, is exported.
    Set<String> exported = new TreeSet<>();
    for (Exports e : descriptor.exports()) {
      check(!e.isQualified(), "qualified export of " + e.source());
      exported.add(e.source());
    }
    check(Set.of("org.owasp.html").equals(exported),
        "exports " + exported + " rather than only org.owasp.html");
    check(descriptor.opens().isEmpty(), "opens " + descriptor.opens());
    check(descriptor.uses().isEmpty(), "uses " + descriptor.uses());
    check(descriptor.provides().isEmpty(), "provides " + descriptor.provides());

    // The bundled shim is inside the module -- so the sanitizer can load it
    // -- but is not exported, so no one else can depend on it.
    check(descriptor.packages().contains("org.owasp.shim"),
        "org.owasp.shim is not a package of the module: "
        + descriptor.packages());
    check(!module.isExported("org.owasp.shim"), "org.owasp.shim is exported");
    check(!module.isOpen("org.owasp.shim"), "org.owasp.shim is open");

    // The only dependences are java.base and, at compile time only, the JSR
    // 305 annotations.  jsr305 is not on the module path here, which a
    // static dependence has to tolerate and a plain one would not.
    Map<String, Set<Requires.Modifier>> requires = new HashMap<>();
    for (Requires r : descriptor.requires()) {
      requires.put(r.name(), r.modifiers());
    }
    check(Set.of("java.base", "jsr305").equals(requires.keySet()),
        "requires " + requires);
    check(requires.get("jsr305").contains(Requires.Modifier.STATIC),
        "jsr305 is not a static dependence: " + requires);
    check(!requires.get("jsr305").contains(Requires.Modifier.TRANSITIVE),
        "jsr305 is a transitive dependence: " + requires);
    check(!ModuleLayer.boot().findModule("jsr305").isPresent(),
        "jsr305 is on the module path, so this run proves nothing about"
        + " the static dependence");

    // Encapsulation holds at run time: the public shim entry point that
    // org.owasp.html calls freely is inaccessible from another module,
    // while the same reflective call into the exported package works.
    try {
      Sanitizers.class.getField("FORMATTING").get(null);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("cannot reach the exported API reflectively", e);
    }
    try {
      Class.forName("org.owasp.shim.Java8Shim").getMethod("j8").invoke(null);
      check(false, "org.owasp.shim.Java8Shim.j8() is accessible from another"
          + " module");
    } catch (IllegalAccessException expected) {
      // Not exported to us: exactly what a real module descriptor buys.
    } catch (ClassNotFoundException | NoSuchMethodException
        | InvocationTargetException e) {
      throw new AssertionError("the shim did not fail in the expected way", e);
    }

    // And the sanitizer works from the module path, which drives the shim
    // loader inside the module.
    String sanitized = Sanitizers.FORMATTING.sanitize(
        "<b onclick=\"steal()\">safe</b><script>alert(1)</script>");
    check("<b>safe</b>".equals(sanitized), "sanitized to " + sanitized);

    System.out.println("owasp.java.html.sanitizer is an explicit module"
        + " exporting only org.owasp.html; " + descriptor);
  }

  private static void check(boolean condition, String failure) {
    if (!condition) {
      throw new AssertionError(failure);
    }
  }
}
