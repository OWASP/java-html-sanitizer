/*
 * Copyright (c) 2013, Kristian Rosenvold
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of OWASP nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
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

import java.util.HashSet;
import java.util.Set;

/**
 * Uses smart matching to match tags
 *
 * @author Kristian Rosenvold
 */
public class TagMatcher {
    private final Set<String> allowedLowercase = new HashSet<String>();

    public TagMatcher(Iterable<String> allowedValues) {
        for (String item : allowedValues) {
            allowedLowercase.add(item.toLowerCase());
        }
    }

    /**
     * Examines if this tag matches the values in this matcher.
     *
     * Please note that this is case-insensitive, which is ok for html and xhtml, but not really for xml
     * @param tagName The tag name to look for
     * @return true if the tag name matches this mach
     */
    public boolean matches(String tagName) {
        return allowedLowercase.contains(tagName.toLowerCase());
    }

    public int size() {
        return allowedLowercase.size();
    }
}
