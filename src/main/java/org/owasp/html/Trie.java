// Copyright (c) 2011, Mike Samuel
// All rights reserved.
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
// Neither the name of the OWASP nor the names of its contributors may
// be used to endorse or promote products derived from this software
// without specific prior written permission.
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * A trie used to separate punctuation tokens in a run of non-whitespace
 * characters by preferring the longest punctuation string possible in a
 * greedy left-to-right scan.
 *
 * @author Mike Samuel (mikesamuel@gmail.com)
 */
final class Trie {
  private final char[] childMap;
  private final Trie[] children;
  private final boolean terminal;
  private final int value;

  /**
   * @param elements not empty, non null.
   */
  public Trie(Map<String, Integer> elements) {
    this(sortedUniqEntries(elements), 0);
  }

  private Trie(List<Map.Entry<String, Integer>> elements, int depth) {
    this(elements, depth, 0, elements.size());
  }

  /**
   * @param elements not empty, non null.  Not modified.
   * @param depth the depth in the tree.
   * @param start an index into punctuationStrings of the first string in this
   *   subtree.
   * @param end an index into punctuationStrings past the last string in this
   *   subtree.
   */
  private Trie(
      List<Map.Entry<String, Integer>> elements, int depth,
      int start, int end) {
    int pos = start;
    this.terminal = depth == elements.get(pos).getKey().length();
    if (this.terminal) {
      this.value = elements.get(pos).getValue();
      if (pos + 1 == end) {  // base case
        this.childMap = ZERO_CHARS;
        this.children = ZERO_TRIES;
        return;
      } else {
        ++pos;
      }
    } else {
      this.value = Integer.MAX_VALUE;
    }
    int childCount = 0;
    {
      int last = -1;
      for (int i = pos; i < end; ++i) {
        char ch = elements.get(i).getKey().charAt(depth);
        if (ch != last) {
          ++childCount;
          last = ch;
        }
      }
    }
    this.childMap = new char[childCount];
    this.children = new Trie[childCount];
    int childStart = pos;
    int childIndex = 0;
    char lastCh = elements.get(pos).getKey().charAt(depth);
    for (int i = pos + 1; i < end; ++i) {
      char ch = elements.get(i).getKey().charAt(depth);
      if (ch != lastCh) {
        childMap[childIndex] = lastCh;
        children[childIndex++] = new Trie(
          elements, depth + 1, childStart, i);
        childStart = i;
        lastCh = ch;
      }
    }
    childMap[childIndex] = lastCh;
    children[childIndex++] = new Trie(elements, depth + 1, childStart, end);
  }

  /** Does this node correspond to a complete string in the input set. */
  public boolean isTerminal() { return terminal; }

  public int getValue() { return value; }

  /**
   * The child corresponding to the given character.
   * @return null if no such trie.
   */
  public Trie lookup(char ch) {
    int i = Arrays.binarySearch(childMap, ch);
    return i >= 0 ? children[i] : null;
  }

  /**
   * The descendant of this trie corresponding to the string for this trie
   * appended with s.
   * @param s non null.
   * @return null if no such trie.
   */
  public Trie lookup(CharSequence s) {
    Trie t = this;
    for (int i = 0, n = s.length(); i < n; ++i) {
      t = t.lookup(s.charAt(i));
      if (null == t) { break; }
    }
    return t;
  }

  public boolean contains(char ch) {
    return Arrays.binarySearch(childMap, ch) >= 0;
  }

  private static <T> List<Map.Entry<String, T>> sortedUniqEntries(
      Map<String, T> m) {
    return new ArrayList<Map.Entry<String, T>>(
        new TreeMap<String, T>(m).entrySet());
  }

  private static final char[] ZERO_CHARS = new char[0];
  private static final Trie[] ZERO_TRIES = new Trie[0];

  /**
   * Append all strings s such that {@code this.lookup(s).isTerminal()} to the
   * given list in lexical order.
   */
  public void toStringList(List<String> strings) {
    toStringList("", strings);
  }

  private void toStringList(String prefix, List<String> strings) {
    if (terminal) { strings.add(prefix); }
    for (int i = 0, n = childMap.length; i < n; ++i) {
      children[i].toStringList(prefix + childMap[i], strings);
    }
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    toStringBuilder(0, sb);
    return sb.toString();
  }

  private void toStringBuilder(int depth, StringBuilder sb) {
    sb.append(terminal ? "terminal" : "nonterminal");
    int childDepth = depth + 1;
    for (int i = 0; i < childMap.length; ++i) {
      sb.append('\n');
      for (int d = 0; d < childDepth; ++d) {
        sb.append('\t');
      }
      sb.append('\'').append(childMap[i]).append("' ");
      children[i].toStringBuilder(childDepth, sb);
    }
  }
}
