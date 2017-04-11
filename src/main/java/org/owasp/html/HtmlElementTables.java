package org.owasp.html;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

/**
 * Metadata about HTML elements.
 */
public final class HtmlElementTables {

  /** Pseudo element index for text nodes. */
  public static final int TEXT_NODE = -1;

  /** Maps between element indices and element names. */
  private final HtmlElementNames elementNames;
  /** Relates elements and the elements that can contain them. */
  private final DenseElementBinaryMatrix canContain;
  /**
   * Relates element names and the elements that are closed when that close
   * tag appears.
   */
  private final DenseElementBinaryMatrix closedOnClose;
  /**
   * Relates element names and the elements that are closed when that open
   * tag appears.
   */
  private final DenseElementBinaryMatrix closedOnOpen;
  /**
   * Close tags besides the tag itself which close the tag.
   */
  private final SparseElementToElements explicitClosers;
  /**
   * Elements in order which are implicitly opened when a descendant tag is
   * lexically nested within an ancestor.
   */
  private final SparseElementMultitable impliedElements;
  /**
   * The kind of character data that can appear in an element.
   */
  private final TextContentModel textContentModel;
  /** The elements that can be resumed after misnested inline tags. */
  private final DenseElementSet resumable;

  private final int DIR_TAG;
  private final int OL_TAG;
  private final int UL_TAG;
  private final int LI_TAG;
  private final int SELECT_TAG;
  private final int OPTION_TAG;
  private final int OPTGROUP_TAG;
  private final int SCRIPT_TAG;
  private final int STYLE_TAG;
  private final int TABLE_TAG;
  private final int TBODY_TAG;
  private final int TFOOT_TAG;
  private final int THEAD_TAG;
  private final int TR_TAG;
  private final int TD_TAG;
  private final int TH_TAG;
  private final int CAPTION_TAG;
  private final int COL_TAG;
  private final int COLGROUP_TAG;
  private final int IFRAME_TAG;

  private final FreeWrapper[] FREE_WRAPPERS;

  private final int[] LI_TAG_ARR;
  private final int[] OPTION_TAG_ARR;

  /** {@code <noscript>}, {@code <noframes>}, etc. */
  private final DenseElementSet nofeatureElements;


  /** */
  public HtmlElementTables(
      HtmlElementNames elementNames,
      DenseElementBinaryMatrix canContain,
      DenseElementBinaryMatrix closedOnClose,
      DenseElementBinaryMatrix closedOnOpen,
      SparseElementToElements explicitClosers,
      SparseElementMultitable impliedElements,
      TextContentModel textContentModel,
      DenseElementSet resumable
      ) {
    this.elementNames = elementNames;
    this.canContain = canContain;
    this.closedOnClose = closedOnClose;
    this.closedOnOpen = closedOnOpen;
    this.explicitClosers = explicitClosers;
    this.impliedElements = impliedElements;
    this.textContentModel = textContentModel;
    this.resumable = resumable;

    // Most of the information above is extracted by interrogating a browser
    // via html-containment.html
    // That does a good job of extracting relationships between elements.
    // It doesn't do such a good job with understanding scoping relationships
    // between elements, so we hard-code some tables needed to allow embedding
    // regardless of element scoping relationships that are extracted from the
    // HTML 5 spec.
    DIR_TAG = indexForName("dir");
    OL_TAG = indexForName("ol");
    UL_TAG = indexForName("ul");
    LI_TAG = indexForName("li");
    SELECT_TAG = indexForName("select");
    OPTION_TAG = indexForName("option");
    OPTGROUP_TAG = indexForName("opgroup");
    SCRIPT_TAG = indexForName("script");
    STYLE_TAG = indexForName("style");
    TABLE_TAG = indexForName("table");
    TBODY_TAG = indexForName("tbody");
    TFOOT_TAG = indexForName("tfoot");
    THEAD_TAG = indexForName("thead");
    TR_TAG = indexForName("tr");
    TD_TAG = indexForName("td");
    TH_TAG = indexForName("th");
    CAPTION_TAG = indexForName("caption");
    COL_TAG = indexForName("col");
    COLGROUP_TAG = indexForName("colgroup");
    IFRAME_TAG = indexForName("iframe");

    ImmutableList<FreeWrapper> freeWrappers = ImmutableList.of(
        new FreeWrapper(
            LI_TAG,
            // LI_TAG is allowed here since an LI can appear when an LI is on
            // top of the stack.  It will be popped and the new LI will be
            // opened.
            new int[] { DIR_TAG, OL_TAG, UL_TAG, LI_TAG },
            new int[] { UL_TAG }),
        new FreeWrapper(
            OPTION_TAG, new int[] { SELECT_TAG, OPTGROUP_TAG, OPTION_TAG },
            new int[] { SELECT_TAG }),
        new FreeWrapper(
            OPTGROUP_TAG, new int[] { SELECT_TAG, OPTGROUP_TAG },
            new int[] { SELECT_TAG }),
        new FreeWrapper(
            TD_TAG, new int[] { TR_TAG, TD_TAG, TH_TAG },
            new int[] { TABLE_TAG, TBODY_TAG, TR_TAG }),
        new FreeWrapper(
            TH_TAG, new int[] { TR_TAG, TD_TAG, TR_TAG },
            new int[] { TABLE_TAG, TBODY_TAG, TR_TAG }),
        new FreeWrapper(
            TR_TAG, new int[] { TBODY_TAG, THEAD_TAG, TFOOT_TAG, TR_TAG },
            new int[] { TABLE_TAG, TBODY_TAG }),
        new FreeWrapper(
            TBODY_TAG, new int[] { TABLE_TAG, THEAD_TAG, TBODY_TAG, TFOOT_TAG },
            new int[] { TABLE_TAG }),
        new FreeWrapper(
            THEAD_TAG, new int[] { TABLE_TAG, THEAD_TAG, TBODY_TAG, TFOOT_TAG },
            new int[] { TABLE_TAG }),
        new FreeWrapper(
            TFOOT_TAG, new int[] { TABLE_TAG, THEAD_TAG, TBODY_TAG, TFOOT_TAG },
            new int[] { TABLE_TAG }),
        new FreeWrapper(
            CAPTION_TAG,
            new int[] { TABLE_TAG },
            new int[] { TABLE_TAG }),
        new FreeWrapper(
            COL_TAG, new int[] { COLGROUP_TAG },
            new int[] { TABLE_TAG, COLGROUP_TAG }),
        new FreeWrapper(
            COLGROUP_TAG, new int[] { TABLE_TAG }, new int[] { TABLE_TAG })
        );
    int maxDescIdx = -1;
    for (FreeWrapper freeWrapper : freeWrappers) {
      maxDescIdx = Math.max(freeWrapper.desc, maxDescIdx);
    }

    FreeWrapper[] freeWrapperArr = new FreeWrapper[maxDescIdx + 1];
    for (FreeWrapper freeWrapper : freeWrappers) {
      freeWrapperArr[freeWrapper.desc] = freeWrapper;
    }

    FREE_WRAPPERS = freeWrapperArr;

    LI_TAG_ARR = new int[] { LI_TAG };
    OPTION_TAG_ARR = new int[] { OPTION_TAG };

    boolean[] nofeatureBits = new boolean[this.nElementTypes()];
    nofeatureBits[indexForName("noscript")] =
        nofeatureBits[indexForName("noframes")] =
            nofeatureBits[indexForName("noembed")] = true;
    this.nofeatureElements = new DenseElementSet(nofeatureBits);
  }


  /** True if parent can directly contain child. */
  public boolean canContain(int parent, int child) {
    if (nofeatureElements.get(parent)) {
      // It's hard to interrogate a browser about the behavior of
      // <noscript> in scriptless mode using JavaScript, and the
      // behavior of <noscript> is more dangerous when in that mode,
      // so we hardcode that mode here as a worst case assumption.
      return true;
    }

    return child == TEXT_NODE
        ? canContainText(parent)
        : canContain.get(parent, child);
  }


  /** The element index for the element with the given name. */
  public int indexForName(String canonName) {
    return elementNames.getElementNameIndex(canonName);
  }

  /** The element index for the element with the given name. */
  public String canonNameForIndex(int index) {
    return elementNames.canonNames.get(index);
  }

  /** The elements that can be resumed after misnested inline tags. */
  public boolean resumable(int index) {
    return resumable.get(index);
  }

  /**
   * Whether parsing can produce an element with the given index that contains
   * a text node.
   */
  public boolean canContainText(int index) {
    return textContentModel.canContainText(index);
  }

  /**
   * Whether parsing can produce an element with the given index that contains
   * a text node that has human readable text instead of script or style
   * source code.
   */
  public boolean canContainPlainText(int index) {
    return textContentModel.canContainPlainText(index)
        // The iframe's content is specified in very odd ways
        // https://dev.w3.org/html5/pf-summary/Overview.html#the-iframe-element
        // """
        // When used in HTML documents, the allowed content model of iframe
        // elements is text, except that invoking the HTML fragment parsing
        // algorithm with the iframe element as the context element and the text
        // contents as the input must result in a list of nodes that are all
        // phrasing content, with no parse errors having occurred, with no
        // script elements being anywhere in the list or as descendants of
        // elements in the list, and with all the elements in the list
        // (including their descendants) being themselves conforming.
        //
        // The iframe element must be empty in XML documents.
        // """
        //
        // The iframe can contain text so canContain is true, but the text is
        // not freeform plain text.  The latter has the effect of making
        // HtmlPolicyBuilder built policies disallow text inside iframe
        // elements.
        && index != IFRAME_TAG
        ;
  }

  boolean canContainComment(int ix) {
    return textContentModel.canContainComment(ix);
  }

  boolean canContainCharacterReference(int ix) {
    return textContentModel.canContainEntities(ix);
  }

  boolean isTextContentRaw(int ix) {
    return textContentModel.isRaw(ix);
  }

  boolean isUnended(int ix) {
    return textContentModel.isUnended(ix);
  }

  boolean isAlternateCloserFor(int closeTag, int openElement) {
    return explicitClosers.get(openElement, closeTag);
  }

  boolean closedOnOpen(int alreadyOpenElement, int openTag) {
    return closedOnOpen.get(alreadyOpenElement, openTag);
  }

  boolean closedOnClose(int alreadyOpenElement, int closeTag) {
    return closedOnClose.get(alreadyOpenElement, closeTag);
  }


  /**
   * The number of element types which is also the exclusive upper bound on
   * element indices.
   */
  public int nElementTypes() {
    return elementNames.canonNames.size();
  }


  private static final class FreeWrapper {

    final int desc;
    final boolean[] allowedContainers;
    final int[] implied;

    FreeWrapper(int desc, int[] allowedContainers, int[] implied) {
      this.desc = desc;
      int maxAllowedContainer = -1;
      for (int allowedContainer : allowedContainers) {
        maxAllowedContainer = Math.max(maxAllowedContainer, allowedContainer);
      }
      this.allowedContainers = new boolean[maxAllowedContainer + 1];
        for (int allowedContainer : allowedContainers) {
        this.allowedContainers[allowedContainer] = true;
      }
      this.implied = implied;
    }
  }

  static final int[] ZERO_INTS = {};

  /**
   * Elements in order which are implicitly opened when a descendant tag is
   * lexically nested within an ancestor.
   */
  int[] impliedElements(int anc, int desc) {
    // <style> and <script> are allowed anywhere.
    if (desc == SCRIPT_TAG || desc == STYLE_TAG) {
      return ZERO_INTS;
    }

    // It's dangerous to allow free <li> tags because of the way an <li>
    // implies a </li> if there is an <li> on the parse stack without a
    // LIST_SCOPE element in the middle.

    // Since we don't control the context in which sanitized HTML is embedded,
    // we can't assume that there isn't a containing <li> tag before parsing
    // starts, so we make sure we never produce an <li> or <td> without a
    // corresponding LIST or TABLE scope element on the stack.
    // <select> is not a scope for <option> elements, but we do that too for
    // symmetry and as an extra degree of safety against future spec changes.
    FreeWrapper wrapper = desc != TEXT_NODE && desc < FREE_WRAPPERS.length
        ? FREE_WRAPPERS[desc] : null;
    if (wrapper != null) {
      if (anc < wrapper.allowedContainers.length
          && !wrapper.allowedContainers[anc]) {
        return wrapper.implied;
      }
    }

    if (desc != TEXT_NODE) {
      int[] implied = impliedElements.getElementIndexList(anc, desc);
      // This handles the table case at least
      if (implied.length != 0) { return implied; }
    }

    // If we require above that all <li>s appear in a <ul> or <ol> then
    // for symmetry, we require here that all content of a <ul> or <ol> appear
    // nested in a <li>.
    // This does not have the same security implications as the above, but is
    // symmetric.
    int[] oneImplied = null;
    if (anc == OL_TAG || anc == UL_TAG) {
      oneImplied = LI_TAG_ARR;
    } else if (anc == SELECT_TAG) {
      oneImplied = OPTION_TAG_ARR;
    }
    if (oneImplied != null) {
      if (desc != oneImplied[0]) {
        return LI_TAG_ARR;
      }
    }
    // TODO: why are we dropping OPTION_AG_ARR?
    return ZERO_INTS;
  }



  /**
   * Get the HTML metadata instance.
   */
  static HtmlElementTables get() {
    return HtmlElementTablesCanned.TABLES;
  }

  /**
   * Maps between element indices and element names.
   */
  public static final class HtmlElementNames {

    /**
     * placeholder name for any element name not defined by the HTML 6
     * specification or any similar document.
     */
    static final String CUSTOM_ELEMENT_NAME = "xcustom";

    /**
     * Canonical element names by element index.
     */
    public final ImmutableList<String> canonNames;
    private transient ImmutableMap<String, Integer> canonNameToIndex;
    private transient int customElementIndex;

    /** */
    public HtmlElementNames(List<String> canonNames) {
      this.canonNames = ImmutableList.copyOf(canonNames);
    }

    /** */
    HtmlElementNames(String... canonNames) {
      this.canonNames = ImmutableList.copyOf(canonNames);
    }

    /**
     * The index of the given element name or otherwise the index of the custom
     * element name
     */
    public int getElementNameIndex(String canonName) {
      if (canonNameToIndex == null) {
        ImmutableMap.Builder<String, Integer> b = ImmutableMap.builder();
        for (int i = 0, n = this.canonNames.size(); i < n; ++i) {
          b.put(this.canonNames.get(i), i);
        }
        canonNameToIndex = b.build();
        this.customElementIndex = canonNames.indexOf(CUSTOM_ELEMENT_NAME);
        Preconditions.checkState(this.customElementIndex >= 0);
      }
      Integer index = canonNameToIndex.get(canonName);
      return index != null ? index.intValue() : customElementIndex;
    }
  }

  /**
   * Given two element names, yields a boolean.
   */
  static final class DenseElementBinaryMatrix {
    private final int matrixLength;
    private final boolean[] bits;

    /** */
    public DenseElementBinaryMatrix(boolean[] bits, int matrixLength) {
      Preconditions.checkArgument(bits.length == matrixLength * matrixLength);
      this.matrixLength = matrixLength;
      this.bits = bits.clone();
    }

    /**
     * @param a the first element name index.
     * @param b the second element name index.
     */
    public boolean get(int a, int b) {
      Preconditions.checkElementIndex(a, matrixLength);
      Preconditions.checkElementIndex(b, matrixLength);
      return bits[a * matrixLength + b];
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      for (int j = 0, k = 0; j < matrixLength; ++j) {
        if (j != 0) { sb.append('\n'); }
        for (int i = 0; i < matrixLength; ++i, ++k) {
          sb.append(bits[k] ? '1' : '.');
        }
      }
      return sb.toString();
    }
  }


  /**
   * A set of elements.
   */
  public static final class DenseElementSet {

    private final boolean[] bits;

    /** */
    public DenseElementSet(boolean[] bits) {
      this.bits = bits.clone();
    }

    /**
     * True iff the element at index i is in the set.
     */
    public boolean get(int i) {
      return bits[i];
    }
  }


  /**
   * Maps element indices to sets of the same.
   */
  public static final class SparseElementToElements {
    private final int[][] arrs;

    /**
     * @param arrs arrays sorted by zero-th element which is the key, and where
     *      where each array from the first element on is a sorted set of
     *      values.
     */
    public SparseElementToElements(int[][] arrs) {
      this.arrs = arrs.clone();
      int last = -1;
      for (int i = 0, n = this.arrs.length; i < n; ++i) {
        int[] arr = arrs[i] = arrs[i].clone();
        Preconditions.checkArgument(last < arr[0]);
        last = arr[0];
        int lastVal = -1;
        for (int j = 1, m = arr.length; j < m; ++j) {
          int val = arr[j];
          Preconditions.checkArgument(val > lastVal, arr);
          lastVal = val;
        }
      }

    }

    boolean get(int key, int value) {
      int row = Arrays.binarySearch(arrs, new int[] { key }, COMPARE_BY_ZEROTH);
      if (row < 0) {
        return false;
      }
      int[] arr = arrs[row];
      return binSearchRange(arr, 1, arr.length, value);
    }
  }


  static boolean binSearchRange(
      int[] arr, int leftIncl, int rightExcl, int value) {
    int lo = leftIncl, hi = rightExcl;
    while (lo < hi) {
      int mid = (lo + hi) >> 1;
      int el = arr[mid];
      int delta = value - el;
      if (delta == 0) {
        return true;
      } else if (delta < 0) {
        hi = mid;
      } else {
        lo = mid + 1;
      }
    }
    return false;

  }

  /**
   * Maps element to elements to lists of elements.
   */
  public static final class SparseElementMultitable {
    private final int[][][] arrs;
    private static final int[][] ZERO_INT_ARRS = new int[0][];

    /**
     * @param arrs an array such that
     *    arrs[aElementIndex] is null or an array, a, sorted by first element
     *    such that the first element is bIndex and the elements after the
     *    zero-th are the element indices that (aElementIndex, bElementIndex)
     *    map to in order.
     */
    public SparseElementMultitable(int[][][] arrs) {
      this.arrs = arrs.clone();
      for (int j = 0, n = arrs.length; j < n; ++j) {
        if (this.arrs[j] == null) {
          this.arrs[j] = ZERO_INT_ARRS;
        } else {
          int[][] arrEl = this.arrs[j] = this.arrs[j].clone();
          for (int i = 0, m = arrEl.length; i < m; ++i) {
            int[] row = arrEl[i] = arrEl[i].clone();
            Preconditions.checkState(
                i == 0 || row[0] > arrEl[i - 1][0]);
          }
        }
      }
    }

    /**
     * The element indices mapped to by (aIndex, bIndex).
     */
    public int[] getElementIndexList(int aIndex, int bIndex) {
      if (aIndex < arrs.length) {
        int[][] aArrs = arrs[aIndex];
        int bi = Arrays.binarySearch(
            aArrs, new int[] { bIndex },
            COMPARE_BY_ZEROTH);
        if (bi >= 0) {
          int[] bIndexThenRow = aArrs[bi];
          int[] row = new int[bIndexThenRow.length - 1];
          System.arraycopy(bIndexThenRow, 1, row, 0, row.length);
          return row;
        }
      }
      return ZERO_INTS;
    }
  }

  /**
   * For each element, the kinds of character data it can contain.
   */
  public static final class TextContentModel {
    private final byte[] contentModelBitsPerElement;

    /** */
    public TextContentModel(byte[] contentModelBitsPerElement) {
      this.contentModelBitsPerElement = contentModelBitsPerElement;
    }

    /**
     * Whether {@code <!--...->} parses to a comment when it appears in the
     * identified element.
     */
    public boolean canContainComment(int elementIndex) {
      return 0 != (
          contentModelBitsPerElement[elementIndex]
          & TextContentModelBit.COMMENTS.bitMask);
    }

    /**
     * Whether {@code &amp;} parses to an HTML character reference when it
     * appears in the identified element.
     */
    public boolean canContainEntities(int elementIndex) {
      return 0 != (
          contentModelBitsPerElement[elementIndex]
          & TextContentModelBit.ENTITIES.bitMask);
    }

    /**
     * Whether parsing can produce an element with the given index that contains
     * a text node.
     */
    public boolean canContainText(int elementIndex) {
      return 0 != (
          contentModelBitsPerElement[elementIndex]
          & TextContentModelBit.TEXT.bitMask);
    }

    /**
     * Whether parsing can produce an element with the given index that contains
     * a text node that has human readable text instead of script or style
     * source code.
     */
    public boolean canContainPlainText(int elementIndex) {
      return 0 != (
          contentModelBitsPerElement[elementIndex]
          & TextContentModelBit.PLAIN_TEXT.bitMask);
    }

    /**
     * True iff things that look like tags when they appear lexically within
     * the element do in fact, parse to tags.
     */
    public boolean isRaw(int elementIndex) {
      return 0 != (
          contentModelBitsPerElement[elementIndex]
          & TextContentModelBit.RAW.bitMask);
    }

    /**
     * True if parsing the element always proceeds to the end of input.
     */
    public boolean isUnended(int elementIndex) {
      return 0 != (
          contentModelBitsPerElement[elementIndex]
          & TextContentModelBit.UNENDED.bitMask);
    }

    /**
     * True if the given model bit is allowed within the element.
     */
    public boolean isAllowed(int elementIndex, TextContentModelBit modelBit) {
      return 0 != (
          contentModelBitsPerElement[elementIndex]
          & modelBit.bitMask);
    }
  }


  /**
   * Describes properties of the content that could be added to an element
   * as a result of a parse that includes its open tag.
   */
  public enum TextContentModelBit {
    /** */
    COMMENTS(1),
    /** */
    ENTITIES(2),
    /** */
    RAW(4),
    /** */
    TEXT(8),
    /** */
    UNENDED(16),
    /** */
    PLAIN_TEXT(32),
    ;

    /** A single bit used internally to identify the bit in packed form. */
    public final int bitMask;

    TextContentModelBit(int bitMask) {
      this.bitMask = bitMask;
    }
  }

  static final Comparator<int[]> COMPARE_BY_ZEROTH =
      new Comparator<int[]>() {
        public int compare(int[] a, int[] b) {
          // Integer.compare is @since JDK 7
          return a[0] - b[0];
        }
      };

  /**
   * Unpacks a boolean[] from an array of ints.
   * This allows us to store largish boolean[]s in relatively small numbers of
   * bytecode instructions.
   */
  public static boolean[] unpack(int[] packed, int length) {
    boolean[] bools = new boolean[length];
    for (int i = 0; i < length; ++i) {
      bools[i] = (packed[i >> 5] & (1 << (i & 0x1f))) != 0;
    }
    return bools;
  }
}
