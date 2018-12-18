/*
 * Copyright (c) 2007-2011, Arshan Dabirsiaghi, Jason Li
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * - Redistributions of source code must retain the above copyright notice,
 * 	 this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of OWASP nor the names of its contributors may be used to
 *   endorse or promote products derived from this software without specific
 *   prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package org.owasp.html.antisamy;

import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * A model for CSS properties and the "rules" they must follow (either literals
 * or regular expressions) in order to be considered valid.
 *
 * @author Jason Li
 *
 */
public class Property {
  private final String name;

    private final List<String> allowedValues;

  private final List<Pattern> allowedRegExp;

  private final List<String> shorthandRefs;

    public Property(String name, List<Pattern> allowedRegexp3, List<String> allowedValue, List<String> shortHandRefs, String description, String onInvalidStr) {
        this.name = name;
        this.allowedRegExp  = Collections.unmodifiableList(allowedRegexp3);
        this.allowedValues = Collections.unmodifiableList(allowedValue);
        this.shorthandRefs = Collections.unmodifiableList(shortHandRefs);
    }

    /**
   * Return a <code>List</code> of allowed regular expressions
   * @return A <code>List</code> of allowed regular expressions.
   */
  public List<Pattern> getAllowedRegExp() {
    return allowedRegExp;
  }

    /**
   * @return A <code>List</code> of allowed literal values.
   */
  public List<String> getAllowedValues() {
    return allowedValues;
  }

    /**
   * @return A <code>List</code> of allowed shorthand references.
   */
  public List<String> getShorthandRefs() {
    return shorthandRefs;
  }

    /**
   *
   * @return The name of the property.
   */
  public String getName() {
    return name;
  }

}
