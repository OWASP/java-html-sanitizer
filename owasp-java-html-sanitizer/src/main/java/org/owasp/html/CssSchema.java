// Copyright (c) 2013, Mike Samuel
// All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package org.owasp.html;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.function.Function;
import static org.owasp.shim.Java8Shim.j8;

import javax.annotation.Nullable;

/** Describes the kinds of tokens a CSS property's value can safely contain. */
@TCB
public final class CssSchema {

  /**
   * Describes how CSS interprets tokens after the ":" for a property.
   * For example, if the property name "color" maps to this, then it
   * should record that '#' literals are innocuous colors, and that functions
   * like "rgb", "rgba", "hsl", etc. are allowed functions.
   */
  public static final class Property {
    /** A bitfield of BIT_* constants describing groups of allowed tokens. */
    final int bits;
    /** Specific allowed values. */
    final Set<String> literals;
    /**
     * Maps lower-case function tokens to the schema key for their parameters.
     */
    final Map<String, String> fnKeys;

    /**
     * @param bits A bitfield of BIT_* constants describing groups of allowed tokens.
     * @param literals Specific allowed values.  Converted to lower case, since
     *     values are matched against a lower-cased token; a literal that was
     *     not lower case could never match.
     * @param fnKeys Maps lower-case function tokens to the schema key for their parameters.
     *     The function tokens are converted to lower case for the same reason.
     */
    public Property(
        int bits, Set<String> literals,
        Map<String, String> fnKeys) {
      this.bits = bits;
      Set<String> literalsBuilder = new HashSet<>();
      for (String literal : literals) {
        literalsBuilder.add(Strings.toLowerCase(literal));
      }
      this.literals = j8().setCopyOf(literalsBuilder);
      Map<String, String> fnKeysBuilder = new HashMap<>();
      for (Map.Entry<String, String> e : fnKeys.entrySet()) {
        fnKeysBuilder.put(Strings.toLowerCase(e.getKey()), e.getValue());
      }
      this.fnKeys = j8().mapCopyOf(fnKeysBuilder);
    }

    /**
     * A bitfield of {@code BIT_*} constants describing groups of allowed
     * tokens.
     */
    public int bits() { return bits; }

    /**
     * The specific values this property allows, as an immutable set.
     */
    public Set<String> literals() { return literals; }

    /**
     * Maps lower-case function tokens such as {@code "rgb("} to the schema key
     * describing their arguments, as an immutable map.
     *
     * <p>A key named here must also be present in the schema, or the function
     * resolves to {@link CssSchema#DISALLOWED} and its values are dropped.
     */
    public Map<String, String> fnKeys() { return fnKeys; }

    /**
     * This property, also allowing the given values.
     *
     * <p>This widens what the property accepts.  Prefer naming the exact
     * values you need over reaching for a broader {@code BIT_*} bit.
     *
     * @param extraLiterals values to add; converted to lower case.
     * @return a new property; this one is unchanged.
     */
    public Property withLiterals(String... extraLiterals) {
      Set<String> widened = new HashSet<>(literals);
      widened.addAll(Arrays.asList(extraLiterals));
      return new Property(bits, widened, fnKeys);
    }

    /**
     * This property, no longer allowing the given values.
     *
     * <p>Values not currently allowed are ignored, so this is safe to use
     * against a schema whose exact contents you have not pinned down.
     *
     * @param unwantedLiterals values to remove; matched case-insensitively.
     * @return a new property; this one is unchanged.
     */
    public Property withoutLiterals(String... unwantedLiterals) {
      Set<String> narrowed = new HashSet<>(literals);
      for (String unwanted : unwantedLiterals) {
        narrowed.remove(Strings.toLowerCase(unwanted));
      }
      return new Property(bits, narrowed, fnKeys);
    }

    /**
     * This property, also allowing the given functions.
     *
     * <p>The schema must also define the keys these map to, or the functions
     * resolve to {@link CssSchema#DISALLOWED}.  {@link CssSchema#withOverrides}
     * checks that for you.
     *
     * @param extraFnKeys maps a lower-case function token such as
     *     {@code "rgb("} to the schema key for its arguments.
     * @return a new property; this one is unchanged.
     */
    public Property withFunctions(Map<String, String> extraFnKeys) {
      Map<String, String> widened = new HashMap<>(fnKeys);
      widened.putAll(extraFnKeys);
      return new Property(bits, literals, widened);
    }

    @Override
    public String toString() {
      return "[CSS property bits=" + bits + " literals=" + new TreeSet<>(literals)
          + " fns=" + new TreeSet<>(fnKeys.keySet()) + "]";
    }

    @Override
    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + bits;
      result = prime * result + ((fnKeys == null) ? 0 : fnKeys.hashCode());
      result = prime * result + ((literals == null) ? 0 : literals.hashCode());
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (obj == null) {
        return false;
      }
      if (getClass() != obj.getClass()) {
        return false;
      }
      Property other = (Property) obj;
      if (bits != other.bits) {
        return false;
      }
      if (fnKeys == null) {
        if (other.fnKeys != null) {
          return false;
        }
      } else if (!fnKeys.equals(other.fnKeys)) {
        return false;
      }
      if (literals == null) {
        if (other.literals != null) {
          return false;
        }
      } else if (!literals.equals(other.literals)) {
        return false;
      }
      return true;
    }
  }

  // These describe the token groups a property's value may contain.  The
  // Property constructor is public and takes them, so they are public too;
  // they were previously package-private, which left callers guessing.
  /** A number, with or without a unit: {@code 4}, {@code 2px}, {@code 50%}. */
  public static final int BIT_QUANTITY = 1;
  /** A hash colour value: {@code #f00}. */
  public static final int BIT_HASH_VALUE = 2;
  /** A negative quantity: {@code -1px}.  Independent of BIT_QUANTITY. */
  public static final int BIT_NEGATIVE = 4;
  /** A quoted string: {@code "foo"}. */
  public static final int BIT_STRING = 8;
  /**
   * A {@code url(...)} value.  Set this only deliberately: CSS URLs are
   * fetched without user interaction, so a property that accepts one is a
   * loading vector.
   */
  public static final int BIT_URL = 16;
  /** A bare word not in the literal set, emitted as a quoted string. */
  public static final int BIT_UNRESERVED_WORD = 64;
  /** A unicode range: {@code U+0-7F}. */
  public static final int BIT_UNICODE_RANGE = 128;

  static final Property DISALLOWED = new Property(
      0, Collections.emptySet(), Collections.emptyMap());

  private final Map<String, Property> properties;

  private CssSchema(Map<String, Property> properties) {
    if (properties == null) { throw new NullPointerException(); }
    this.properties = properties;
  }

  /**
   * A schema that includes all and only the named properties.
   *
   * @param propertyNames a series of lower-case CSS property names that appear
   *    in the built-in CSS definitions.  It is an error to mention an unknown
   *    property name.  This class's {@code main} method will dump a list of
   *    known property names when run with zero arguments.
   */
  public static CssSchema withProperties(
      Iterable<? extends String> propertyNames) {
    Map<String, Property> propertiesBuilder =
        new HashMap<>();
    for (String propertyName : propertyNames) {
      Property prop = DEFINITIONS.get(propertyName);
      if (prop == null) { throw new IllegalArgumentException(propertyName); }
      propertiesBuilder.put(propertyName, prop);
    }
    return new CssSchema(Collections.unmodifiableMap(propertiesBuilder));
  }

  /**
   * A schema that includes all and only the named properties.
   *
   * @param properties maps lower-case CSS property names to property objects.
   */
  public static CssSchema withProperties(
      Map<? extends String, ? extends Property> properties) {
    Map<String, Property> propertyMapBuilder =
        new HashMap<>();
    // check that all fnKeys are defined in properties.
    for (Map.Entry<? extends String, ? extends Property> e : properties.entrySet()) {
      Property property = e.getValue();
      for (String fnKey : property.fnKeys.values()) {
        if (!properties.containsKey(fnKey)) {
          throw new IllegalArgumentException(
              "Property map is not self contained: \"" + e.getKey()
              + "\" uses the function key \"" + fnKey
              + "\" which the map does not define."
              + "  Add it to the map, or build on a schema that already has"
              + " it with CssSchema.withOverrides.");
        }
      }
      propertyMapBuilder.put(e.getKey(), e.getValue());
    }
    return new CssSchema(Collections.unmodifiableMap(propertyMapBuilder));
  }

  /**
   * A schema that represents the union of the input schemas.
   *
   * @return A schema that allows all and only CSS properties that are allowed
   *    by at least one of the inputs.
   * <p>Two schemas that define the same property differently cannot be
   * reconciled automatically -- silently picking a winner would hand the
   * caller a policy they did not write -- so this throws instead.  To extend
   * or narrow a property that a schema already defines, say which one wins
   * with {@link #withOverrides}.
   *
   * @throws IllegalArgumentException if two schemas have properties with the
   *    same name, but different (per .equals) {@link Property} values.
   */
  public static CssSchema union(CssSchema... cssSchemas) {
    if (cssSchemas.length == 1) { return cssSchemas[0]; }
    Map<String, Property> propertyMapBuilder = new LinkedHashMap<>();
    for (CssSchema cssSchema : cssSchemas) {
      for (Map.Entry<String, Property> e : cssSchema.properties.entrySet()) {
        String name = e.getKey();
        Property newProp = e.getValue();
        if (Objects.isNull(name)) {
          throw new NullPointerException("An entry was returned with null key from cssSchema.properties");
        }
        if (Objects.isNull(newProp)) {
          throw new NullPointerException("An entry was returned with null value from cssSchema.properties");
        }
        Property oldProp = propertyMapBuilder.put(name, newProp);
        if (oldProp != null && !oldProp.equals(newProp)) {
          throw new IllegalArgumentException(
              "Duplicate irreconcilable definitions for " + name);
        }
      }
    }
    return new CssSchema(Collections.unmodifiableMap(propertyMapBuilder));
  }

  /**
   * A schema that allows only what every input schema allows.
   *
   * <p>Where the inputs define the same property differently, the definitions
   * are themselves intersected: a token group is kept only if every input
   * allows it, a value only if every input lists it, and a function only if
   * every input maps it to the same argument schema.  So the result is never
   * wider than any input, whatever the inputs disagree about -- unlike
   * {@link #union}, which refuses to reconcile a disagreement at all.
   *
   * <p>This is what {@link PolicyFactory#and} needs: combining two policies
   * narrows what either allows on its own.
   *
   * @param cssSchemas the schemas to intersect.  Intersecting none of them is
   *     meaningless rather than universal, so at least one is required.
   * @return a schema that allows a CSS property only if all of the inputs do.
   */
  public static CssSchema intersection(CssSchema... cssSchemas) {
    if (cssSchemas.length == 0) {
      throw new IllegalArgumentException("No schemas to intersect");
    }
    if (cssSchemas.length == 1) { return cssSchemas[0]; }
    Map<String, Property> propertyMapBuilder =
        new LinkedHashMap<>(cssSchemas[0].properties);
    for (int i = 1; i < cssSchemas.length; ++i) {
      Map<String, Property> other = cssSchemas[i].properties;
      Iterator<Map.Entry<String, Property>> it =
          propertyMapBuilder.entrySet().iterator();
      while (it.hasNext()) {
        Map.Entry<String, Property> e = it.next();
        Property narrower = other.get(e.getKey());
        if (narrower == null) {
          it.remove();
        } else {
          e.setValue(intersectProperties(e.getValue(), narrower));
        }
      }
    }
    return new CssSchema(Collections.unmodifiableMap(propertyMapBuilder));
  }

  /** The definition allowing only what both of the inputs allow. */
  private static Property intersectProperties(Property a, Property b) {
    if (a.equals(b)) { return a; }
    Set<String> literals = new HashSet<>(a.literals);
    literals.retainAll(b.literals);
    Map<String, String> fnKeys = new HashMap<>();
    for (Map.Entry<String, String> e : a.fnKeys.entrySet()) {
      // Keep a function only where both sides send its arguments to the same
      // schema key; two different argument schemas cannot be reconciled here
      // without inventing a third, so drop it.
      if (e.getValue().equals(b.fnKeys.get(e.getKey()))) {
        fnKeys.put(e.getKey(), e.getValue());
      }
    }
    return new Property(a.bits & b.bits, literals, fnKeys);
  }

  /**
   * The set of CSS properties allowed by this schema.
   *
   * @return an immutable set.
   */
  public Set<String> allowedProperties() {
    return properties.keySet();
  }

  /**
   * The definition this schema uses for a property, so that it can be used as
   * the basis of a modified one.
   *
   * @param propertyName a lower-case CSS property name, or a schema key for a
   *     function's arguments such as {@code "rgb()"}.
   * @return null if this schema does not allow the property.
   */
  public @Nullable Property property(String propertyName) {
    return properties.get(Strings.toLowerCase(propertyName));
  }

  /**
   * This schema with the named properties replaced or added.
   *
   * <p>{@link #union} refuses to reconcile two definitions of the same
   * property; this is how you say which one wins.  Use it to extend, narrow
   * or replace what a schema -- typically {@link #DEFAULT} -- allows for a
   * property, without rebuilding the schema from scratch:
   *
   * <pre>{@code
   * CssSchema schema = CssSchema.DEFAULT.withOverrides(
   *     Collections.singletonMap(
   *         "cursor",
   *         CssSchema.DEFAULT.property("cursor").withLiterals("zoom-in")));
   * }</pre>
   *
   * <p>Function keys are resolved against the combined schema, so a property
   * may refer to a function this schema already defines without the caller
   * having to supply that definition again:
   *
   * <pre>{@code
   * // "linear-gradient()" is already in DEFAULT, so naming it is enough.
   * CssSchema.DEFAULT.withOverrides(Collections.singletonMap(
   *     "background-image",
   *     CssSchema.DEFAULT.property("background-image")
   *         .withFunctions(Collections.singletonMap(
   *             "linear-gradient(", "linear-gradient()"))));
   * }</pre>
   *
   * <p><b>This can widen what the schema accepts</b>, which is the point, but
   * it means the result is only as safe as the definitions you supply.  Adding
   * {@link #BIT_URL} to a property, or wiring in a function key the schema
   * resolves loosely, opens whatever that implies.
   *
   * @param overrides maps lower-case property names to their new definitions.
   *     A name this schema does not have is added.
   * @return a new schema; this one is unchanged.
   * @throws IllegalArgumentException if an override names a function key that
   *     neither it nor this schema defines.
   */
  public CssSchema withOverrides(
      Map<? extends String, ? extends Property> overrides) {
    Map<String, Property> merged = new HashMap<>(properties);
    for (Map.Entry<? extends String, ? extends Property> e
         : overrides.entrySet()) {
      merged.put(
          Strings.toLowerCase(Objects.requireNonNull(e.getKey())),
          Objects.requireNonNull(e.getValue()));
    }
    // Only the overrides can introduce a dangling function key; the schema we
    // started from was checked when it was built.
    for (Map.Entry<? extends String, ? extends Property> e
         : overrides.entrySet()) {
      for (String fnKey : e.getValue().fnKeys.values()) {
        if (!merged.containsKey(fnKey)) {
          throw new IllegalArgumentException(
              "Override for \"" + e.getKey() + "\" uses the function key \""
              + fnKey + "\" which neither the override nor the schema"
              + " defines.  Add a definition for it to the overrides.");
        }
      }
    }
    return new CssSchema(Collections.unmodifiableMap(merged));
  }

  /**
   * An {@link AttributePolicy} that sanitizes a {@code style} attribute value
   * against this schema, dropping every {@code url(...)} value it contains.
   *
   * <p>This is the per-element counterpart of
   * {@link HtmlPolicyBuilder#allowStyling(CssSchema)}, which applies one
   * schema to the {@code style} attribute of every element.  Passing the
   * result to {@link HtmlPolicyBuilder.AttributeBuilder#matching(AttributePolicy)}
   * lets different elements allow different CSS properties:
   *
   * <pre>{@code
   * new HtmlPolicyBuilder()
   *     .allowElements("span", "table")
   *     .allowAttributes("style")
   *         .matching(CssSchema.withProperties(
   *              Arrays.asList("color", "background-color")).toAttributePolicy())
   *         .onElements("span")
   *     .allowAttributes("style")
   *         .matching(CssSchema.withProperties(
   *              Arrays.asList("width", "height")).toAttributePolicy())
   *         .onElements("table")
   *     .toFactory();
   * }</pre>
   *
   * <p><b>Security note:</b> a policy built this way is <b>not</b> wired to
   * {@link HtmlPolicyBuilder#allowUrlsInStyles(AttributePolicy)} or
   * {@link HtmlPolicyBuilder#allowUrlProtocols(String...)}.  That wiring
   * happens only inside the {@code style} attribute guard that
   * {@link HtmlPolicyBuilder#allowStyling()} installs, and it cannot see a
   * policy handed to {@code matching}.  Rather than let URLs through
   * unvetted, this variant drops them all; use
   * {@link #toAttributePolicy(Function)} to vet them yourself.
   *
   * @return an attribute policy suitable for the {@code style} attribute.
   */
  public AttributePolicy toAttributePolicy() {
    return new StylingPolicy(this, REJECT_ALL_URLS);
  }

  /**
   * An {@link AttributePolicy} that sanitizes a {@code style} attribute value
   * against this schema, passing the content of each {@code url(...)} value
   * through {@code urlRewriter}.
   *
   * <p><b>Security note:</b> as with {@link #toAttributePolicy()}, a policy
   * built this way is <b>not</b> wired to
   * {@link HtmlPolicyBuilder#allowUrlsInStyles(AttributePolicy)} or
   * {@link HtmlPolicyBuilder#allowUrlProtocols(String...)}, so vetting URLs
   * is entirely the caller's job.  URLs in CSS are typically loaded without
   * user interaction, the way {@code <img src=...>} is, so a greater degree
   * of scrutiny is warranted than for a link.  If in doubt, prefer
   * {@link #toAttributePolicy()}, which drops them.
   *
   * <p>To vet URLs by protocol the way {@link HtmlPolicyBuilder} does, reuse
   * a {@link FilterUrlByProtocolAttributePolicy}.  It ignores the element and
   * attribute names it is given, so any will do:
   *
   * <pre>{@code
   * AttributePolicy urlPolicy = new FilterUrlByProtocolAttributePolicy(
   *     Arrays.asList("https", "mailto"));
   * schema.toAttributePolicy(url -> urlPolicy.apply("img", "src", url));
   * }</pre>
   *
   * <p>If an element also gets a {@code style} policy from
   * {@link HtmlPolicyBuilder#allowStyling()}, the two are joined, and joining
   * narrows: the schemas intersect, and both rewriters run in turn, so either
   * one can drop a URL.  A policy attached here therefore restricts the
   * element it is attached to; it cannot grant it a property the global
   * schema withholds.
   *
   * @param urlRewriter receives the decoded content of a {@code url(...)}
   *     value and returns the URL to use, or {@code null} or the empty string
   *     to drop it.  It is never passed {@code null} or the empty string.
   * @return an attribute policy suitable for the {@code style} attribute.
   */
  public AttributePolicy toAttributePolicy(
      Function<String, String> urlRewriter) {
    return new StylingPolicy(this, Objects.requireNonNull(urlRewriter));
  }

  /** Drops every URL it is given. */
  private static final Function<String, String> REJECT_ALL_URLS
      = new Function<String, String>() {
        public @Nullable String apply(String url) {
          return null;
        }
      };

  /** The schema for the named property or function key. */
  Property forKey(String propertyName) {
    String propertyNameCanon = Strings.toLowerCase(propertyName);
    Property property = properties.get(propertyNameCanon);
    if (property != null) { return property; }
    int n = propertyNameCanon.length();
    if (n != 0 && propertyNameCanon.charAt(0) == '-') {
      String barePropertyNameCanon = stripVendorPrefix(propertyNameCanon);
      if (barePropertyNameCanon == null) { return DISALLOWED; }
      property = properties.get(barePropertyNameCanon);
      if (property != null) { return property; }
    }
    return DISALLOWED;
  }

  /** {@code "-moz-foo"} &rarr; {@code "foo"}. */
  private static @Nullable String stripVendorPrefix(String cssKeyword) {
    int prefixLen = 0;
    if (cssKeyword.length() >= 2) {
      switch (cssKeyword.charAt(1)) {
        case 'm':
          if (cssKeyword.startsWith("-ms-")) {
            prefixLen = 4;
          } else if (cssKeyword.startsWith("-moz-")) {
            prefixLen = 5;
          }
          break;
        case 'o':
          if (cssKeyword.startsWith("-o-")) { prefixLen = 3; }
          break;
        case 'w':
          if (cssKeyword.startsWith("-webkit-")) { prefixLen = 8; }
          break;
        default: break;
      }
    }
    return prefixLen == 0 ? null : cssKeyword.substring(prefixLen);
  }

  /**
   * The CSS-wide keywords, which every CSS property accepts as its entire
   * value.  They only ever reset a property to a value the cascade already
   * chose, so they carry no attacker-controlled content.
   *
   * @see <a href="https://www.w3.org/TR/css-cascade-4/#defaulting-keywords"
   *   >CSS Cascade 4, Explicit Defaulting</a>
   */
  static final Set<String> CSS_WIDE_KEYWORDS = j8().setOf(
      "inherit", "initial", "revert", "revert-layer", "unset");

  /** Maps lower-cased CSS property names to information about them. */
  static final Map<String, Property> DEFINITIONS;
  static {
    Map<String, String> zeroFns = Collections.emptyMap();
    Map<String, Property> builder = new HashMap<>();
    Set<String> mozBorderRadiusLiterals0 = j8().setOf("/");
    Set<String> mozOpacityLiterals0 = j8().setOf("inherit");
    Set<String> mozOutlineLiterals0 = j8().setOf(
        "aliceblue", "antiquewhite", "aqua", "aquamarine", "azure", "beige",
        "bisque", "black", "blanchedalmond", "blue", "blueviolet", "brown",
        "burlywood", "cadetblue", "chartreuse", "chocolate", "coral",
        "cornflowerblue", "cornsilk", "crimson", "cyan", "darkblue", "darkcyan",
        "darkgoldenrod", "darkgray", "darkgreen", "darkkhaki", "darkmagenta",
        "darkolivegreen", "darkorange", "darkorchid", "darkred", "darksalmon",
        "darkseagreen", "darkslateblue", "darkslategray", "darkturquoise",
        "darkviolet", "deeppink", "deepskyblue", "dimgray", "dodgerblue",
        "firebrick", "floralwhite", "forestgreen", "fuchsia", "gainsboro",
        "ghostwhite", "gold", "goldenrod", "gray", "green", "greenyellow",
        "honeydew", "hotpink", "indianred", "indigo", "ivory", "khaki",
        "lavender", "lavenderblush", "lawngreen", "lemonchiffon", "lightblue",
        "lightcoral", "lightcyan", "lightgoldenrodyellow", "lightgreen",
        "lightgrey", "lightpink", "lightsalmon", "lightseagreen",
        "lightskyblue", "lightslategray", "lightsteelblue", "lightyellow",
        "lime", "limegreen", "linen", "magenta", "maroon", "mediumaquamarine",
        "mediumblue", "mediumorchid", "mediumpurple", "mediumseagreen",
        "mediumslateblue", "mediumspringgreen", "mediumturquoise",
        "mediumvioletred", "midnightblue", "mintcream", "mistyrose",
        "moccasin", "navajowhite", "navy", "oldlace", "olive", "olivedrab",
        "orange", "orangered", "orchid", "palegoldenrod", "palegreen",
        "paleturquoise", "palevioletred", "papayawhip", "peachpuff", "peru",
        "pink", "plum", "powderblue", "purple", "red", "rosybrown", "royalblue",
        "saddlebrown", "salmon", "sandybrown", "seagreen", "seashell", "sienna",
        "silver", "skyblue", "slateblue", "slategray", "snow", "springgreen",
        "steelblue", "tan", "teal", "thistle", "tomato", "turquoise", "violet",
        "wheat", "white", "whitesmoke", "yellow", "yellowgreen");
    Set<String> mozOutlineLiterals1 = j8().setOf(
        "dashed", "dotted", "double", "groove", "outset", "ridge", "solid");
    Set<String> mozOutlineLiterals2 = j8().setOf("thick", "thin");
    Set<String> mozOutlineLiterals3 = j8().setOf(
        "hidden", "inherit", "inset", "invert", "medium", "none");
    Map<String, String> mozOutlineFunctions = j8().mapOfEntries(
        j8().mapEntry("rgb(", "rgb()"), j8().mapEntry("rgba(", "rgba()"),
        j8().mapEntry("hsl(", "hsl()"), j8().mapEntry("hsla(", "hsla()"));
    Set<String> mozOutlineColorLiterals0 =
      j8().setOf("inherit", "invert");
    Set<String> mozOutlineStyleLiterals0 =
      j8().setOf("hidden", "inherit", "inset", "none");
    Set<String> mozOutlineWidthLiterals0 =
      j8().setOf("inherit", "medium");
    Set<String> oTextOverflowLiterals0 =
      j8().setOf("clip", "ellipsis");
    Set<String> azimuthLiterals0 = j8().setOf(
        "behind", "center-left", "center-right", "far-left", "far-right",
        "left-side", "leftwards", "right-side", "rightwards");
    Set<String> azimuthLiterals1 = j8().setOf("left", "right");
    Set<String> azimuthLiterals2 =
      j8().setOf("center", "inherit");
    Set<String> backgroundLiterals0 = j8().setOf(
        "border-box", "contain", "content-box", "cover", "padding-box");
    Set<String> backgroundLiterals1 =
      j8().setOf("no-repeat", "repeat-x", "repeat-y", "round", "space");
    Set<String> backgroundLiterals2 = j8().setOf("bottom", "top");
    Set<String> backgroundLiterals3 = j8().setOf(
        ",", "/", "auto", "center", "fixed", "inherit", "local", "none",
        "repeat", "scroll", "transparent");
    Map<String, String> backgroundFunctions = j8().mapOfEntries(
      j8().mapEntry("image(", "image()"),
      j8().mapEntry("linear-gradient(", "linear-gradient()"),
      j8().mapEntry("radial-gradient(", "radial-gradient()"),
      j8().mapEntry("repeating-linear-gradient(", "repeating-linear-gradient()"),
      j8().mapEntry("repeating-radial-gradient(", "repeating-radial-gradient()"),
      j8().mapEntry("conic-gradient(", "conic-gradient()"),
      j8().mapEntry("repeating-conic-gradient(", "repeating-conic-gradient()"),
      j8().mapEntry("rgb(", "rgb()"), j8().mapEntry("rgba(", "rgba()"),
      j8().mapEntry("hsl(", "hsl()"), j8().mapEntry("hsla(", "hsla()"));
    Set<String> backgroundAttachmentLiterals0 =
      j8().setOf(",", "fixed", "local", "scroll");
    Set<String> backgroundColorLiterals0 =
      j8().setOf("inherit", "transparent");
    Set<String> backgroundImageLiterals0 =
      j8().setOf(",", "none");
    Map<String, String> backgroundImageFunctions =
      j8().mapOfEntries(
        j8().mapEntry("image(", "image()"),
        j8().mapEntry("linear-gradient(", "linear-gradient()"),
        j8().mapEntry("radial-gradient(", "radial-gradient()"),
        j8().mapEntry("repeating-linear-gradient(", "repeating-linear-gradient()"),
        j8().mapEntry("repeating-radial-gradient(", "repeating-radial-gradient()"),
        j8().mapEntry("conic-gradient(", "conic-gradient()"),
        j8().mapEntry("repeating-conic-gradient(", "repeating-conic-gradient()"));
    Set<String> backgroundPositionLiterals0 = j8().setOf(
        ",", "center");
    Set<String> backgroundRepeatLiterals0 = j8().setOf(
        ",", "repeat");
    Set<String> borderLiterals0 = j8().setOf(
        "hidden", "inherit", "inset", "medium", "none", "transparent");
    Set<String> borderCollapseLiterals0 = j8().setOf(
        "collapse", "inherit", "separate");
    Set<String> bottomLiterals0 = j8().setOf("auto", "inherit");
    Set<String> boxShadowLiterals0 = j8().setOf(
        ",", "inset", "none");
    // Arithmetic inside calc().  Operands are limited to numbers, dimensions
    // and percentages, so nested functions such as var(), attr() and url()
    // are stripped.  A bare "-" lexes as an identifier rather than as
    // punctuation, but both paths consult this literal set.
    Set<String> calc$FunLiterals0 = j8().setOf(
        "+", "-", "*", "/", "(", ")");
    Map<String, String> calcFunctions = j8().mapOfEntries(
        j8().mapEntry("calc(", "calc()"));
    Set<String> clearLiterals0 = j8().setOf(
        "both", "inherit", "none");
    Map<String, String> clipFunctions =
        j8().mapOfEntries(j8().mapEntry("rect(", "rect()"));
    Set<String> contentLiterals0 = j8().setOf("none", "normal");
    Set<String> cueLiterals0 = j8().setOf("inherit", "none");
    Set<String> cursorLiterals0 = j8().setOf(
        "all-scroll", "col-resize", "crosshair", "default", "e-resize",
        "hand", "help", "move", "n-resize", "ne-resize", "no-drop",
        "not-allowed", "nw-resize", "pointer", "progress", "row-resize",
        "s-resize", "se-resize", "sw-resize", "text", "vertical-text",
        "w-resize", "wait");
    Set<String> cursorLiterals1 = j8().setOf(
        ",", "auto", "inherit");
    Set<String> directionLiterals0 = j8().setOf("ltr", "rtl");
    Set<String> displayLiterals0 = j8().setOf(
        "-moz-inline-box", "-moz-inline-stack", "block", "inline",
        "inline-block", "inline-table", "list-item", "run-in", "table",
        "table-caption", "table-cell", "table-column", "table-column-group",
        "table-footer-group", "table-header-group", "table-row",
        "table-row-group",
        // Flexbox and grid formatting contexts.  "display" is not in
        // DEFAULT_WHITELIST, so these only take effect for a policy that
        // opts into layout; see the note above GRID/FLEX below.
        "flex", "inline-flex", "grid", "inline-grid", "flow-root");
    Set<String> elevationLiterals0 = j8().setOf(
        "above", "below", "higher", "level", "lower");
    Set<String> emptyCellsLiterals0 = j8().setOf("hide", "show");
    //Map<String, String> filterFunctions =
    //  j8().mapOfEntries(mapEntry("alpha(", "alpha()"));
    Set<String> fontLiterals0 = j8().setOf(
        "100", "200", "300", "400", "500", "600", "700", "800", "900", "bold",
        "bolder", "lighter");
    Set<String> fontLiterals1 = j8().setOf(
        "large", "larger", "small", "smaller", "x-large", "x-small",
        "xx-large", "xx-small", "xxx-large", "medium");
    Set<String> fontLiterals2 = j8().setOf(
        "caption", "icon", "menu", "message-box", "small-caption",
        "status-bar");
    Set<String> fontLiterals3 = j8().setOf(
        "cursive", "fantasy", "monospace", "sans-serif", "serif");
    Set<String> fontLiterals4 = j8().setOf("italic", "oblique");
    Set<String> fontLiterals5 = j8().setOf(
        ",", "/", "inherit", "medium", "normal", "small-caps");
    Set<String> fontFamilyLiterals0 = j8().setOf(",", "inherit");
    Set<String> fontStretchLiterals0 = j8().setOf(
        "condensed", "expanded", "extra-condensed", "extra-expanded",
        "narrower", "semi-condensed", "semi-expanded", "ultra-condensed",
        "ultra-expanded", "wider");
    Set<String> fontStretchLiterals1 = j8().setOf("normal");
    Set<String> fontStyleLiterals0 = j8().setOf(
        "inherit", "normal");
    Set<String> fontVariantLiterals0 = j8().setOf(
        "inherit", "normal", "small-caps");
    Set<String> listStyleLiterals0 = j8().setOf(
        "armenian", "cjk-decimal", "decimal", "decimal-leading-zero", "disc",
        "disclosure-closed", "disclosure-open", "ethiopic-numeric", "georgian",
        "hebrew", "hiragana", "hiragana-iroha", "japanese-formal",
        "japanese-informal", "katakana", "katakana-iroha",
        "korean-hangul-formal", "korean-hanja-formal",
        "korean-hanja-informal", "lower-alpha", "lower-greek", "lower-latin",
        "lower-roman", "simp-chinese-formal", "simp-chinese-informal",
        "square", "trad-chinese-formal", "trad-chinese-informal",
        "upper-alpha", "upper-latin", "upper-roman");
    Set<String> listStyleLiterals1 = j8().setOf(
        "inside", "outside");
    Set<String> listStyleLiterals2 = j8().setOf(
        "circle", "inherit", "none");
    Set<String> maxHeightLiterals0 = j8().setOf(
        "auto", "inherit", "none");
    Set<String> overflowLiterals0 = j8().setOf(
        "auto", "hidden", "inherit", "scroll", "visible");
    Set<String> overflowWrapLiterals0 = j8().setOf(
        "normal", "break-word", "anywhere", "inherit");
    Set<String> overflowXLiterals0 = j8().setOf(
        "no-content", "no-display");
    Set<String> overflowXLiterals1 = j8().setOf(
        "auto", "hidden", "scroll", "visible");
    Set<String> pageBreakAfterLiterals0 = j8().setOf(
        "always", "auto", "avoid", "inherit");
    Set<String> pageBreakInsideLiterals0 = j8().setOf(
        "auto", "avoid", "inherit");
    Set<String> pitchLiterals0 = j8().setOf(
        "high", "low", "x-high", "x-low");
    Set<String> playDuringLiterals0 = j8().setOf(
        "auto", "inherit", "mix", "none", "repeat");
    Set<String> positionLiterals0 = j8().setOf(
        "absolute", "relative", "static");
    Set<String> speakLiterals0 = j8().setOf(
        "inherit", "none", "normal", "spell-out");
    Set<String> speakHeaderLiterals0 = j8().setOf(
        "always", "inherit", "once");
    Set<String> speakNumeralLiterals0 = j8().setOf(
        "continuous", "digits");
    Set<String> speakPunctuationLiterals0 = j8().setOf(
        "code", "inherit", "none");
    Set<String> speechRateLiterals0 = j8().setOf(
        "fast", "faster", "slow", "slower", "x-fast", "x-slow");
    Set<String> tableLayoutLiterals0 = j8().setOf(
        "auto", "fixed", "inherit");
    Set<String> textAlignLiterals0 = j8().setOf(
        "center", "end", "inherit", "justify", "justify-all", "match-parent",
        "start", "left", "right", "initial", "revert", "revert-layer", "unset");
    Set<String> textDecorationLiterals0 = j8().setOf(
        "blink", "line-through", "overline", "underline");
    Set<String> textDecorationStyleLiterals0 = j8().setOf(
        "dashed", "dotted", "double", "solid", "wavy");
    Set<String> textDecorationLineLiterals0 = j8().setOf(
        "blink", "grammar-error", "line-through", "none", "overline",
        "spelling-error", "underline");
    Set<String> textDecorationThicknessLiterals0 = j8().setOf(
        "auto", "from-font");
    Set<String> textTransformLiterals0 = j8().setOf(
        "capitalize", "lowercase", "uppercase");
    Set<String> textWrapLiterals0 = j8().setOf(
        "suppress", "unrestricted");
    Set<String> unicodeBidiLiterals0 = j8().setOf(
        "bidi-override", "embed");
    Set<String> verticalAlignLiterals0 = j8().setOf(
        "baseline", "middle", "sub", "super", "text-bottom", "text-top");
    Set<String> visibilityLiterals0 = j8().setOf(
        "collapse", "hidden", "inherit", "visible");
    Set<String> voiceFamilyLiterals0 = j8().setOf(
        "child", "female", "male");
    Set<String> volumeLiterals0 = j8().setOf(
        "loud", "silent", "soft", "x-loud", "x-soft");
    Set<String> whiteSpaceLiterals0 = j8().setOf(
        "-moz-pre-wrap", "-o-pre-wrap", "-pre-wrap", "nowrap", "pre",
        "pre-line", "pre-wrap");
    Set<String> wordBreakLiterals0 = j8().setOf(
        "break-all", "break-word", "keep-all", "normal");
    Set<String> wordWrapLiterals0 = j8().setOf(
        "anywhere", "break-word", "normal");
    Set<String> rgb$FunLiterals0 = j8().setOf(",");
    Set<String> linearGradient$FunLiterals0 = j8().setOf(
        ",", "to");
    Set<String> radialGradient$FunLiterals0 = j8().setOf(
        "at", "closest-corner", "closest-side", "ellipse", "farthest-corner",
        "farthest-side");
    Set<String> radialGradient$FunLiterals1 = j8().setOf(
        ",", "center", "circle");
    Set<String> rect$FunLiterals0 = j8().setOf(",", "auto");
    //Set<String> alpha$FunLiterals0 = j8().setOf("=", "opacity");
    Property mozBorderRadius =
       new Property(5, mozBorderRadiusLiterals0, zeroFns);
    builder.put("-moz-border-radius", mozBorderRadius);
    Property mozBorderRadiusBottomleft =
       new Property(5, j8().setOf(), zeroFns);
    builder.put("-moz-border-radius-bottomleft", mozBorderRadiusBottomleft);
    Property mozOpacity = new Property(1, mozOpacityLiterals0, zeroFns);
    builder.put("-moz-opacity", mozOpacity);
    @SuppressWarnings("unchecked")
    Property mozOutline = new Property(
        7,
        union(mozOutlineLiterals0, mozOutlineLiterals1, mozOutlineLiterals2,
              mozOutlineLiterals3),
        mozOutlineFunctions);
    builder.put("-moz-outline", mozOutline);
    @SuppressWarnings("unchecked")
    Property mozOutlineColor = new Property(
        2, union(mozOutlineColorLiterals0, mozOutlineLiterals0),
        mozOutlineFunctions);
    builder.put("-moz-outline-color", mozOutlineColor);
    @SuppressWarnings("unchecked")
    Property mozOutlineStyle = new Property(
        0, union(mozOutlineLiterals1, mozOutlineStyleLiterals0), zeroFns);
    builder.put("-moz-outline-style", mozOutlineStyle);
    @SuppressWarnings("unchecked")
    Property mozOutlineWidth = new Property(
        5, union(mozOutlineLiterals2, mozOutlineWidthLiterals0), zeroFns);
    builder.put("-moz-outline-width", mozOutlineWidth);
    Property oTextOverflow = new Property(0, oTextOverflowLiterals0, zeroFns);
    builder.put("-o-text-overflow", oTextOverflow);
    @SuppressWarnings("unchecked")
    Property azimuth = new Property(
        5, union(azimuthLiterals0, azimuthLiterals1, azimuthLiterals2),
        zeroFns);
    builder.put("azimuth", azimuth);
    @SuppressWarnings("unchecked")
    Property background = new Property(
        23,
        union(azimuthLiterals1, backgroundLiterals0, backgroundLiterals1,
              backgroundLiterals2, backgroundLiterals3, mozOutlineLiterals0),
        backgroundFunctions);
    builder.put("background", background);
    builder.put("background-attachment",
                new Property(0, backgroundAttachmentLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property backgroundColor = new Property(
        258, union(backgroundColorLiterals0, mozOutlineLiterals0),
        mozOutlineFunctions);
    builder.put("background-color", backgroundColor);
    builder.put("background-image",
                new Property(16, backgroundImageLiterals0,
                             backgroundImageFunctions));
    @SuppressWarnings("unchecked")
    Property backgroundPosition = new Property(
        5,
        union(azimuthLiterals1, backgroundLiterals2,
              backgroundPositionLiterals0),
        zeroFns);
    builder.put("background-position", backgroundPosition);
    @SuppressWarnings("unchecked")
    Property backgroundRepeat = new Property(
        0, union(backgroundLiterals1, backgroundRepeatLiterals0), zeroFns);
    builder.put("background-repeat", backgroundRepeat);
    @SuppressWarnings("unchecked")
    Property border = new Property(
        7,
        union(borderLiterals0, mozOutlineLiterals0, mozOutlineLiterals1,
              mozOutlineLiterals2),
        mozOutlineFunctions);
    builder.put("border", border);
    @SuppressWarnings("unchecked")
    Property borderBottomColor = new Property(
        2, union(backgroundColorLiterals0, mozOutlineLiterals0),
        mozOutlineFunctions);
    builder.put("border-bottom-color", borderBottomColor);
    builder.put("border-collapse",
                new Property(0, borderCollapseLiterals0, zeroFns));
    Property borderSpacing = new Property(5, mozOpacityLiterals0, zeroFns);
    builder.put("border-spacing", borderSpacing);
    Property bottom = new Property(5, bottomLiterals0, zeroFns);
    builder.put("bottom", bottom);
    @SuppressWarnings("unchecked")
    Property boxShadow = new Property(
        7, union(boxShadowLiterals0, mozOutlineLiterals0), mozOutlineFunctions);
    builder.put("box-shadow", boxShadow);
    @SuppressWarnings("unchecked")
    Property captionSide = new Property(
        0, union(backgroundLiterals2, mozOpacityLiterals0), zeroFns);
    builder.put("caption-side", captionSide);
    @SuppressWarnings("unchecked")
    Property clear = new Property(
        0, union(azimuthLiterals1, clearLiterals0), zeroFns);
    builder.put("clear", clear);
    builder.put("clip", new Property(0, bottomLiterals0, clipFunctions));
    @SuppressWarnings("unchecked")
    Property color = new Property(
        258, union(mozOpacityLiterals0, mozOutlineLiterals0),
        mozOutlineFunctions);
    builder.put("color", color);
    builder.put("content", new Property(8, contentLiterals0, zeroFns));
    Property cue = new Property(16, cueLiterals0, zeroFns);
    builder.put("cue", cue);
    @SuppressWarnings("unchecked")
    Property cursor = new Property(
        272, union(cursorLiterals0, cursorLiterals1), zeroFns);
    builder.put("cursor", cursor);
    @SuppressWarnings("unchecked")
    Property direction = new Property(
        0, union(directionLiterals0, mozOpacityLiterals0), zeroFns);
    builder.put("direction", direction);
    @SuppressWarnings("unchecked")
    Property display = new Property(
        0, union(cueLiterals0, displayLiterals0), zeroFns);
    builder.put("display", display);
    @SuppressWarnings("unchecked")
    Property elevation = new Property(
        5, union(elevationLiterals0, mozOpacityLiterals0), zeroFns);
    builder.put("elevation", elevation);
    @SuppressWarnings("unchecked")
    Property emptyCells = new Property(
        0, union(emptyCellsLiterals0, mozOpacityLiterals0), zeroFns);
    builder.put("empty-cells", emptyCells);
    //builder.put("filter",
    //            new Property(0, j8().setOf(), filterFunctions));
    @SuppressWarnings("unchecked")
    Property cssFloat = new Property(
        0, union(azimuthLiterals1, cueLiterals0), zeroFns);
    builder.put("float", cssFloat);
    @SuppressWarnings("unchecked")
    Property font = new Property(
        73,
        union(fontLiterals0, fontLiterals1, fontLiterals2, fontLiterals3,
              fontLiterals4, fontLiterals5),
        zeroFns);
    builder.put("font", font);
    @SuppressWarnings("unchecked")
    Property fontFamily = new Property(
        72, union(fontFamilyLiterals0, fontLiterals3), zeroFns);
    builder.put("font-family", fontFamily);
    @SuppressWarnings("unchecked")
    Property fontSize = new Property(
        1, union(fontLiterals1, mozOutlineWidthLiterals0), zeroFns);
    builder.put("font-size", fontSize);
    @SuppressWarnings("unchecked")
    Property fontStretch = new Property(
        0, union(fontStretchLiterals0, fontStretchLiterals1), zeroFns);
    builder.put("font-stretch", fontStretch);
    @SuppressWarnings("unchecked")
    Property fontStyle = new Property(
        0, union(fontLiterals4, fontStyleLiterals0), zeroFns);
    builder.put("font-style", fontStyle);
    builder.put("font-variant", new Property(
        0, fontVariantLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property fontWeight = new Property(
        0, union(fontLiterals0, fontStyleLiterals0), zeroFns);
    builder.put("font-weight", fontWeight);
    Property height = new Property(5, bottomLiterals0, calcFunctions);
    builder.put("height", height);
    // top, left and right take the same values as height but are not on the
    // default white-list and do not admit calc().
    Property offset = new Property(5, bottomLiterals0, zeroFns);
    Property letterSpacing = new Property(5, fontStyleLiterals0, zeroFns);
    builder.put("letter-spacing", letterSpacing);
    builder.put("line-height", new Property(1, fontStyleLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property listStyle = new Property(
        16,
        union(listStyleLiterals0, listStyleLiterals1, listStyleLiterals2),
        backgroundImageFunctions);
    builder.put("list-style", listStyle);
    builder.put("list-style-image", new Property(
        16, cueLiterals0, backgroundImageFunctions));
    @SuppressWarnings("unchecked")
    Property listStylePosition = new Property(
        0, union(listStyleLiterals1, mozOpacityLiterals0), zeroFns);
    builder.put("list-style-position", listStylePosition);
    @SuppressWarnings("unchecked")
    Property listStyleType = new Property(
        0, union(listStyleLiterals0, listStyleLiterals2), zeroFns);
    builder.put("list-style-type", listStyleType);
    Property margin = new Property(1, bottomLiterals0, zeroFns);
    builder.put("margin", margin);
    // width, min-width and min-height take the same values as margin but
    // also admit calc().
    Property width = new Property(1, bottomLiterals0, calcFunctions);
    Property maxHeight = new Property(1, maxHeightLiterals0, calcFunctions);
    builder.put("max-height", maxHeight);
    Property opacity = new Property(1, mozOpacityLiterals0, zeroFns);
    builder.put("opacity", opacity);
    builder.put("overflow", new Property(0, overflowLiterals0, zeroFns));
    builder.put("overflow-wrap", new Property(0, overflowWrapLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property overflowX = new Property(
        0, union(overflowXLiterals0, overflowXLiterals1), zeroFns);
    builder.put("overflow-x", overflowX);
    Property padding = new Property(1, mozOpacityLiterals0, zeroFns);
    builder.put("padding", padding);
    @SuppressWarnings("unchecked")
    Property pageBreakAfter = new Property(
        0, union(azimuthLiterals1, pageBreakAfterLiterals0), zeroFns);
    builder.put("page-break-after", pageBreakAfter);
    builder.put("page-break-inside", new Property(
        0, pageBreakInsideLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property pitch = new Property(
        5, union(mozOutlineWidthLiterals0, pitchLiterals0), zeroFns);
    builder.put("pitch", pitch);
    builder.put("play-during", new Property(
        16, playDuringLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property position = new Property(
        0, union(mozOpacityLiterals0, positionLiterals0), zeroFns);
    builder.put("position", position);
    builder.put("quotes", new Property(8, cueLiterals0, zeroFns));
    builder.put("speak", new Property(0, speakLiterals0, zeroFns));
    builder.put("speak-header", new Property(
        0, speakHeaderLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property speakNumeral = new Property(
        0, union(mozOpacityLiterals0, speakNumeralLiterals0), zeroFns);
    builder.put("speak-numeral", speakNumeral);
    builder.put("speak-punctuation", new Property(
        0, speakPunctuationLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property speechRate = new Property(
        5, union(mozOutlineWidthLiterals0, speechRateLiterals0), zeroFns);
    builder.put("speech-rate", speechRate);
    builder.put("table-layout", new Property(
        0, tableLayoutLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property textAlign = new Property(
        0, union(azimuthLiterals1, textAlignLiterals0), zeroFns);
    builder.put("text-align", textAlign);
    @SuppressWarnings("unchecked")
    // The shorthand takes a line, a style and a colour in any order, so it
    // admits everything the three longhands below do.
    Property textDecoration = new Property(
        2,
        union(cueLiterals0, textDecorationLiterals0,
              textDecorationStyleLiterals0, mozOutlineLiterals0),
        mozOutlineFunctions);
    builder.put("text-decoration", textDecoration);
    @SuppressWarnings("unchecked")
    Property textTransform = new Property(
        0, union(cueLiterals0, textTransformLiterals0), zeroFns);
    builder.put("text-transform", textTransform);
    @SuppressWarnings("unchecked")
    Property textWrap = new Property(
        0, union(contentLiterals0, textWrapLiterals0), zeroFns);
    builder.put("text-wrap", textWrap);
    @SuppressWarnings("unchecked")
    Property unicodeBidi = new Property(
        0, union(fontStyleLiterals0, unicodeBidiLiterals0), zeroFns);
    builder.put("unicode-bidi", unicodeBidi);
    @SuppressWarnings("unchecked")
    Property verticalAlign = new Property(
        5,
        union(backgroundLiterals2, mozOpacityLiterals0, verticalAlignLiterals0),
        zeroFns);
    builder.put("vertical-align", verticalAlign);
    builder.put("visibility", new Property(0, visibilityLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property voiceFamily = new Property(
        8, union(fontFamilyLiterals0, voiceFamilyLiterals0), zeroFns);
    builder.put("voice-family", voiceFamily);
    @SuppressWarnings("unchecked")
    Property volume = new Property(
        1, union(mozOutlineWidthLiterals0, volumeLiterals0), zeroFns);
    builder.put("volume", volume);
    @SuppressWarnings("unchecked")
    Property whiteSpace = new Property(
        0, union(fontStyleLiterals0, whiteSpaceLiterals0), zeroFns);
    builder.put("white-space", whiteSpace);
    builder.put("word-break", new Property(0, wordBreakLiterals0, zeroFns));
    builder.put("word-wrap", new Property(0, wordWrapLiterals0, zeroFns));
    builder.put("zoom", new Property(1, fontStretchLiterals1, zeroFns));
    Property rgb$Fun = new Property(1, rgb$FunLiterals0, zeroFns);
    builder.put("rgb()", rgb$Fun);
    builder.put("rgba()", rgb$Fun);
    builder.put("hsl()", rgb$Fun);
    builder.put("hsla()", rgb$Fun);
    builder.put("calc()", new Property(5, calc$FunLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property image$Fun = new Property(
        18, union(mozOutlineLiterals0, rgb$FunLiterals0), mozOutlineFunctions);
    builder.put("image()", image$Fun);
    @SuppressWarnings("unchecked")
    Property linearGradient$Fun = new Property(
        7,
        union(azimuthLiterals1, backgroundLiterals2,
              linearGradient$FunLiterals0, mozOutlineLiterals0),
        mozOutlineFunctions);
    builder.put("linear-gradient()", linearGradient$Fun);
    @SuppressWarnings("unchecked")
    Property radialGradient$Fun = new Property(
        7,
        union(azimuthLiterals1, backgroundLiterals2, mozOutlineLiterals0,
              radialGradient$FunLiterals0, radialGradient$FunLiterals1),
        mozOutlineFunctions);
    builder.put("radial-gradient()", radialGradient$Fun);
    builder.put("rect()", new Property(5, rect$FunLiterals0, zeroFns));
    //builder.put("alpha()", new Property(1, alpha$FunLiterals0, zeroFns));
    builder.put("-moz-border-radius-bottomright", mozBorderRadiusBottomleft);
    builder.put("-moz-border-radius-topleft", mozBorderRadiusBottomleft);
    builder.put("-moz-border-radius-topright", mozBorderRadiusBottomleft);
    builder.put("-moz-box-shadow", boxShadow);
    builder.put("-webkit-border-bottom-left-radius", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-bottom-right-radius",
                mozBorderRadiusBottomleft);
    builder.put("-webkit-border-radius", mozBorderRadius);
    builder.put("-webkit-border-radius-bottom-left", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-radius-bottom-right",
                mozBorderRadiusBottomleft);
    builder.put("-webkit-border-radius-top-left", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-radius-top-right", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-top-left-radius", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-top-right-radius", mozBorderRadiusBottomleft);
    builder.put("-webkit-box-shadow", boxShadow);
    builder.put("border-bottom", border);
    builder.put("border-bottom-left-radius", mozBorderRadiusBottomleft);
    builder.put("border-bottom-right-radius", mozBorderRadiusBottomleft);
    builder.put("border-bottom-style", mozOutlineStyle);
    builder.put("border-bottom-width", mozOutlineWidth);
    builder.put("border-color", borderBottomColor);
    builder.put("border-left", border);
    builder.put("border-left-color", borderBottomColor);
    builder.put("border-left-style", mozOutlineStyle);
    builder.put("border-left-width", mozOutlineWidth);
    builder.put("border-radius", mozBorderRadius);
    builder.put("border-right", border);
    builder.put("border-right-color", borderBottomColor);
    builder.put("border-right-style", mozOutlineStyle);
    builder.put("border-right-width", mozOutlineWidth);
    builder.put("border-style", mozOutlineStyle);
    builder.put("border-top", border);
    builder.put("border-top-color", borderBottomColor);
    builder.put("border-top-left-radius", mozBorderRadiusBottomleft);
    builder.put("border-top-right-radius", mozBorderRadiusBottomleft);
    builder.put("border-top-style", mozOutlineStyle);
    builder.put("border-top-width", mozOutlineWidth);
    builder.put("border-width", mozOutlineWidth);
    builder.put("cue-after", cue);
    builder.put("cue-before", cue);
    builder.put("left", offset);
    builder.put("margin-bottom", margin);
    builder.put("margin-left", margin);
    builder.put("margin-right", margin);
    builder.put("margin-top", margin);
    builder.put("max-width", maxHeight);
    builder.put("min-height", width);
    builder.put("min-width", width);
    builder.put("outline", mozOutline);
    builder.put("outline-color", mozOutlineColor);
    builder.put("outline-style", mozOutlineStyle);
    builder.put("outline-width", mozOutlineWidth);
    builder.put("overflow-y", overflowX);
    builder.put("padding-bottom", padding);
    builder.put("padding-left", padding);
    builder.put("padding-right", padding);
    builder.put("padding-top", padding);
    builder.put("page-break-before", pageBreakAfter);
    builder.put("pause", borderSpacing);
    builder.put("pause-after", borderSpacing);
    builder.put("pause-before", borderSpacing);
    builder.put("pitch-range", borderSpacing);
    builder.put("richness", borderSpacing);
    builder.put("right", offset);
    builder.put("stress", borderSpacing);
    builder.put("text-indent", borderSpacing);
    builder.put("text-overflow", oTextOverflow);
    builder.put("text-shadow", boxShadow);
    builder.put("top", offset);
    builder.put("width", width);
    builder.put("word-spacing", letterSpacing);
    builder.put("z-index", bottom);
    builder.put("repeating-linear-gradient()", linearGradient$Fun);
    builder.put("repeating-radial-gradient()", radialGradient$Fun);
    // ---- Decorative additions (safe for DEFAULT) -------------------------
    // These only change how an element paints itself.  They cannot move it,
    // hide it, or change how it participates in layout, so they go in
    // DEFAULT_WHITELIST alongside the properties they complement.

    builder.put("text-decoration-line",
                new Property(0, textDecorationLineLiterals0, zeroFns));
    builder.put("text-decoration-style",
                new Property(0, textDecorationStyleLiterals0, zeroFns));
    // Same shape as "color": a hash value, a named colour, or rgb()/hsl().
    builder.put("text-decoration-color", color);
    builder.put("text-decoration-thickness",
                new Property(1, textDecorationThicknessLiterals0, zeroFns));

    // SVG paint.  BIT_URL is deliberately not set: "stroke: url(#gradient)"
    // would be a URL vector, and a paint server reference is not worth one.
    @SuppressWarnings("unchecked")
    Set<String> strokeLiterals0 = union(
        mozOutlineLiterals0, j8().setOf("currentcolor", "none", "transparent"));
    builder.put("stroke", new Property(2, strokeLiterals0, mozOutlineFunctions));
    builder.put("stroke-width", new Property(1, j8().setOf(), zeroFns));

    // conic-gradient is an <image> like its linear and radial siblings, so it
    // takes the same shape as radial-gradient().
    @SuppressWarnings("unchecked")
    Property conicGradient$Fun = new Property(
        7,
        union(azimuthLiterals1, backgroundLiterals2, mozOutlineLiterals0,
              j8().setOf(",", "at", "from")),
        mozOutlineFunctions);
    builder.put("conic-gradient()", conicGradient$Fun);
    builder.put("repeating-conic-gradient()", conicGradient$Fun);

    // ---- Layout and transforms (definitions only, NOT in DEFAULT) --------
    // DEFAULT deliberately withholds every property that changes how an
    // element takes part in page layout -- display, position, float, clear,
    // overflow, z-index, opacity, visibility and the offsets -- so that a
    // style attribute can restyle content but cannot reposition it, overlay
    // something else, or hide it.  The families below are the modern
    // equivalents and are withheld on the same grounds.
    //
    // They are defined here so that a policy that wants them can opt in:
    //
    //   CssSchema layout = CssSchema.withProperties(Arrays.asList(
    //       "display", "grid-template-columns", "gap", "repeat()", "minmax()"));
    //   CssSchema schema = CssSchema.union(CssSchema.DEFAULT, layout);
    //
    // Note the "repeat()" and "minmax()" entries: a function is reached
    // through a schema key, and a key the schema does not contain resolves to
    // DISALLOWED, so a property must be opted into together with the
    // functions its values use.

    Set<String> gridTrackLiterals0 = j8().setOf(
        ",", "/", "auto", "auto-fill", "auto-fit", "max-content", "min-content",
        "none", "span", "masonry", "subgrid");
    Map<String, String> gridTrackFunctions = j8().mapOfEntries(
        j8().mapEntry("repeat(", "repeat()"),
        j8().mapEntry("minmax(", "minmax()"),
        j8().mapEntry("fit-content(", "fit-content()"),
        j8().mapEntry("calc(", "calc()"));

    Property minmax$Fun = new Property(1, gridTrackLiterals0, zeroFns);
    builder.put("minmax()", minmax$Fun);
    builder.put("fit-content()", new Property(1, j8().setOf(","), zeroFns));
    // repeat() may nest minmax() and fit-content().
    builder.put("repeat()",
                new Property(1, gridTrackLiterals0, gridTrackFunctions));

    Property gridTemplate = new Property(1, gridTrackLiterals0, gridTrackFunctions);
    for (String name : new String[] {
        "grid", "grid-template", "grid-template-columns", "grid-template-rows",
        "grid-auto-columns", "grid-auto-rows" }) {
      builder.put(name, gridTemplate);
    }
    // Area names are quoted strings; they are never rendered as text.
    builder.put("grid-template-areas", new Property(8, j8().setOf("none"), zeroFns));
    builder.put("grid-auto-flow",
                new Property(0, j8().setOf("column", "dense", "row"), zeroFns));
    // Line-based placement: integers (which may be negative), "span", "auto"
    // and the "/" that separates start from end.
    Property gridLine = new Property(
        5, j8().setOf(",", "/", "auto", "span"), zeroFns);
    for (String name : new String[] {
        "grid-area", "grid-column", "grid-column-end", "grid-column-start",
        "grid-row", "grid-row-end", "grid-row-start" }) {
      builder.put(name, gridLine);
    }
    Property gap = new Property(1, j8().setOf("normal"), zeroFns);
    for (String name : new String[] {
        "gap", "row-gap", "column-gap",
        "grid-gap", "grid-row-gap", "grid-column-gap" }) {
      builder.put(name, gap);
    }

    Set<String> flexWrapLiterals0 = j8().setOf(
        "nowrap", "wrap", "wrap-reverse");
    Set<String> flexDirectionLiterals0 = j8().setOf(
        "column", "column-reverse", "row", "row-reverse");
    Set<String> flexBasisLiterals0 = j8().setOf(
        "auto", "content", "fit-content", "max-content", "min-content");
    builder.put("flex-direction", new Property(0, flexDirectionLiterals0, zeroFns));
    builder.put("flex-wrap", new Property(0, flexWrapLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property flexFlow = new Property(
        0, union(flexDirectionLiterals0, flexWrapLiterals0), zeroFns);
    builder.put("flex-flow", flexFlow);
    builder.put("flex-grow", new Property(1, j8().setOf(), zeroFns));
    builder.put("flex-shrink", new Property(1, j8().setOf(), zeroFns));
    @SuppressWarnings("unchecked")
    Property flexBasis = new Property(
        1, union(flexBasisLiterals0, j8().setOf("none")), zeroFns);
    builder.put("flex-basis", flexBasis);
    @SuppressWarnings("unchecked")
    Property flex = new Property(
        1, union(flexBasisLiterals0, j8().setOf("none", "initial")), zeroFns);
    builder.put("flex", flex);
    // "order" is one of the few layout properties that takes a negative.
    builder.put("order", new Property(5, j8().setOf(), zeroFns));

    Set<String> alignmentLiterals0 = j8().setOf(
        "baseline", "center", "end", "first", "flex-end", "flex-start", "last",
        "left", "normal", "right", "safe", "self-end", "self-start",
        "space-around", "space-between", "space-evenly", "start", "stretch",
        "unsafe");
    Property alignment = new Property(0, alignmentLiterals0, zeroFns);
    @SuppressWarnings("unchecked")
    Property alignmentOrAuto = new Property(
        0, union(alignmentLiterals0, j8().setOf("auto")), zeroFns);
    for (String name : new String[] {
        "align-content", "align-items", "justify-content", "justify-items",
        "place-content", "place-items" }) {
      builder.put(name, alignment);
    }
    for (String name : new String[] {
        "align-self", "justify-self", "place-self" }) {
      builder.put(name, alignmentOrAuto);
    }

    // Transforms can move, scale and rotate an element, which is why they are
    // withheld from DEFAULT for the same reason "position" is.
    Property transform$Fun = new Property(5, j8().setOf(","), zeroFns);
    builder.put("transform-function()", transform$Fun);
    Map<String, String> transformFunctions;
    {
      Map<String, String> fns = new HashMap<>();
      for (String fn : new String[] {
          "translate", "translatex", "translatey", "translatez", "translate3d",
          "rotate", "rotatex", "rotatey", "rotatez", "rotate3d",
          "scale", "scalex", "scaley", "scalez", "scale3d",
          "skew", "skewx", "skewy",
          "matrix", "matrix3d", "perspective" }) {
        fns.put(fn + "(", "transform-function()");
      }
      transformFunctions = Collections.unmodifiableMap(fns);
    }
    builder.put("transform",
                new Property(0, j8().setOf("none"), transformFunctions));
    builder.put("transform-origin", new Property(
        5,
        j8().setOf("bottom", "center", "left", "right", "top"),
        zeroFns));

    // Fold the CSS-wide keywords into every property, rather than repeating
    // them in each literal set above.  Keys ending in "()" describe the
    // arguments of a function, not a property, and are left alone: "initial"
    // is a value for "color", not for the red channel of "rgb(...)".
    // Definitions are shared between properties -- "pause-after" and
    // "richness" are the same object -- so widen each distinct one once and
    // keep the sharing.
    Map<Property, Property> widened = new IdentityHashMap<>();
    for (Map.Entry<String, Property> e : builder.entrySet()) {
      if (e.getKey().endsWith("()")) { continue; }
      Property narrow = e.getValue();
      Property wide = widened.get(narrow);
      if (wide == null) {
        @SuppressWarnings("unchecked")
        Set<String> literals = union(narrow.literals, CSS_WIDE_KEYWORDS);
        wide = new Property(narrow.bits, literals, narrow.fnKeys);
        widened.put(narrow, wide);
      }
      e.setValue(wide);
    }
    DEFINITIONS = Collections.unmodifiableMap(builder);
  }

  private static <T> Set<T> union(Set<T>... subsets) {
    Set<T> all = new HashSet<>();
    for (Set<T> subset : subsets) {
      all.addAll(subset);
    }
    return Collections.unmodifiableSet(all);
  }

  static final Set<String> DEFAULT_WHITELIST = j8().setOf(
      "-moz-border-radius",
      "-moz-border-radius-bottomleft",
      "-moz-border-radius-bottomright",
      "-moz-border-radius-topleft",
      "-moz-border-radius-topright",
      "-moz-box-shadow",
      "-moz-outline",
      "-moz-outline-color",
      "-moz-outline-style",
      "-moz-outline-width",
      "-o-text-overflow",
      "-webkit-border-bottom-left-radius",
      "-webkit-border-bottom-right-radius",
      "-webkit-border-radius",
      "-webkit-border-radius-bottom-left",
      "-webkit-border-radius-bottom-right",
      "-webkit-border-radius-top-left",
      "-webkit-border-radius-top-right",
      "-webkit-border-top-left-radius",
      "-webkit-border-top-right-radius",
      "-webkit-box-shadow",
      "azimuth",
      "background",
      "background-attachment",
      "background-color",
      "background-image",
      "background-position",
      "background-repeat",
      "border",
      "border-bottom",
      "border-bottom-color",
      "border-bottom-left-radius",
      "border-bottom-right-radius",
      "border-bottom-style",
      "border-bottom-width",
      "border-collapse",
      "border-color",
      "border-left",
      "border-left-color",
      "border-left-style",
      "border-left-width",
      "border-radius",
      "border-right",
      "border-right-color",
      "border-right-style",
      "border-right-width",
      "border-spacing",
      "border-style",
      "border-top",
      "border-top-color",
      "border-top-left-radius",
      "border-top-right-radius",
      "border-top-style",
      "border-top-width",
      "border-width",
      "box-shadow",
      "calc()",
      "caption-side",
      "color",
      "cue",
      "cue-after",
      "cue-before",
      "direction",
      "elevation",
      "empty-cells",
      "font",
      "font-family",
      "font-size",
      "font-stretch",
      "font-style",
      "font-variant",
      "font-weight",
      "height",
      "image()",
      "letter-spacing",
      "line-height",
      "linear-gradient()",
      "list-style",
      "list-style-image",
      "list-style-position",
      "list-style-type",
      "margin",
      "margin-bottom",
      "margin-left",
      "margin-right",
      "margin-top",
      "max-height",
      "max-width",
      "min-height",
      "min-width",
      "outline",
      "outline-color",
      "outline-style",
      "outline-width",
      "padding",
      "padding-bottom",
      "padding-left",
      "padding-right",
      "padding-top",
      "pause",
      "pause-after",
      "pause-before",
      "pitch",
      "pitch-range",
      "quotes",
      "radial-gradient()",
      "conic-gradient()",
      "repeating-conic-gradient()",
      "rect()",
      "repeating-linear-gradient()",
      "repeating-radial-gradient()",
      "rgb()",
      "rgba()",
      "hsl()",
      "hsla()",
      "richness",
      "speak",
      "speak-header",
      "speak-numeral",
      "speak-punctuation",
      "speech-rate",
      "stress",
      "stroke",
      "stroke-width",
      "table-layout",
      "text-align",
      "text-decoration",
      "text-decoration-color",
      "text-decoration-line",
      "text-decoration-style",
      "text-decoration-thickness",
      "text-indent",
      "text-overflow",
      "text-shadow",
      "text-transform",
      "text-wrap",
      "unicode-bidi",
      "vertical-align",
      "voice-family",
      "volume",
      "white-space",
      "width",
      "word-spacing",
      "word-wrap"
  );

  /**
   * A schema that includes only those properties on the default schema
   * white-list.
   */
  public static final CssSchema DEFAULT =
      CssSchema.withProperties(DEFAULT_WHITELIST);

  /** Dumps key and literal list to stdout for easy examination. */
  public static void main(String... argv) {
    SortedSet<String> keys = new TreeSet<>();
    SortedSet<String> literals = new TreeSet<>();

    for (Map.Entry<String, Property> e : DEFINITIONS.entrySet()) {
      keys.add(e.getKey());
      literals.addAll(e.getValue().literals);
    }

    System.out.println(
        "# Below two blocks of tokens.\n"
            + "#\n"
        + "# First are all property names.\n"
        + "# Those followed by an asterisk (*) are in the default white-list.\n"
        + "#\n"
        + "# Second are the literal tokens recognized in any defined property\n"
        + "# value.\n"
        );
    for (String key : keys) {
      System.out.print(key);
      if (DEFAULT_WHITELIST.contains(key)) { System.out.print("*"); }
      System.out.println();
    }
    System.out.println();
    for (String literal : literals) {
      System.out.println(literal);
    }
  }
}
