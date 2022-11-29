package org.owasp.html.empiricism;

import org.owasp.html.HtmlElementTables;
import org.owasp.html.HtmlElementTables.HtmlElementNames;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;

/**
 * Can be run thus:
 * <pre>
 * mvn exec:java \
 * -Dexec.mainClass=org.owasp.html.empiricism.JsonToSerializedHtmlElementTables
 * </pre>
 */
public final class JsonToSerializedHtmlElementTables {

  static final class SourceLineWriter {
    final StringBuilder indent = new StringBuilder();
    final StringBuilder sb = new StringBuilder();

    void lines(CharSequence... lines) {
      for (CharSequence line : lines) { line(line); }
    }

    void line(CharSequence cs) {
      int n = cs.length();
      if (n != 0) {
        int lt = 0;
        for (; lt < n; ++lt) {
          char c = cs.charAt(lt);
          if (c == '}' || c == ')') {
            indent.setLength(indent.length() - 2);
          } else {
            break;
          }
        }
        sb.append(indent);
        sb.append(cs);
        for (; lt < n; ++lt) {
          char c = cs.charAt(lt);
          if (c == '{' || c == '(') {
            indent.append(' ').append(' ');
          } else if (c == '}' || c == ')') {
            indent.setLength(indent.length() - 2);
          }
        }
      }
      sb.append('\n');
    }

    void write(int[][] arr) {
      line("new int[][] {");
      writeEls(arr);
      line("}");
    }

    private void writeEls(int[][] arr) {
      for (int i = 0, n = arr.length; i < n; ++i) {
        line("{");
        writeEls(arr[i]);
        line(i + 1 != n ? "}," : "}");
      }
    }

    void write(int[] arr) {
      line("new int[] {");
      writeEls(arr);
      line("}");
    }

    private void writeEls(int[] arr) {
      StringBuilder buf = new StringBuilder();
      for (int i = 0, n = arr.length; i < n; ++i) {
        if (i != 0) {
          buf.append(',');
          if (i % 16 == 0 && buf.length() != 0) {
            line(buf);
            buf.setLength(0);
          } else {
            buf.append(' ');
          }
        }
        buf.append(arr[i]);
      }
      if (buf.length() != 0) {
        line(buf);
      }
    }

    private void writeEls(byte[] arr) {
      StringBuilder buf = new StringBuilder();
      for (int i = 0, n = arr.length; i < n; ++i) {
        if (i != 0) {
          buf.append(',');
          if (i % 16 == 0 && buf.length() != 0) {
            line(buf);
            buf.setLength(0);
          } else {
            buf.append(' ');
          }
        }
        buf.append("(byte)").append(arr[i]);
      }
      if (buf.length() != 0) {
        line(buf);
      }
    }

    void writePacked(boolean[] arr) {
      int[] packed = new int[(arr.length + 31) / 32];
      for (int i = 0, n = arr.length; i < n; ++i) {
        if (arr[i]) {
          packed[i >> 5] |= (1 << (i & 0x1f));
        }
      }
      boolean[] reunpacked = HtmlElementTables.unpack(packed, arr.length);
      Preconditions.checkState(Arrays.equals(arr, reunpacked));
      line("HtmlElementTables.unpack(new int[] {");
      writeEls(packed);
      line("}, " + arr.length + ")");
    }

    void write(byte[] arr) {
      line("new byte[] {");
      writeEls(arr);
      line("}");
    }

    String getSource() {
      return sb.toString();
    }

    void write(int[][][] arrs) {
      line("new int[][][] {");
      for (int j = 0, m = arrs.length; j < m; ++j) {
        int[][] arr = arrs[j];
        if (arr == null) {
          line(j + 1 != m ? "null," : "null");
        } else {
          line("{");
          writeEls(arr);
          line(j + 1 != m ? "}," : "}");
        }
      }
      line("}");
    }

    void write(String[] arr) {
      line("new String[] {");
      writeEls(arr);
      line("}");
    }

    private void writeEls(String[] arr) {
      StringBuilder buf = new StringBuilder();
      for (int i = 0, n = arr.length; i < n; ++i) {
        if (i != 0) {
          buf.append(',');
          if (i % 16 == 0 && buf.length() != 0) {
            line(buf);
            buf.setLength(0);
          } else {
            buf.append(' ');
          }
        }
        String s = arr[i];
        buf.append('"');
        for (int j = 0, m = s.length(); j < m; ++j) {
          char c = s.charAt(j);
          switch (c) {
            case '\n': buf.append("\\n"); break;
            case '\r': buf.append("\\r"); break;
            case '\\': buf.append("\\\\"); break;
            case '"': buf.append("\\\""); break;
            case '(': case ')': case '{': case '}':  // Don't interfere with indent
              buf.append("\\u00");
              buf.append(Integer.toHexString(c));
              break;
            default:
              buf.append(c);
          }
        }
        buf.append('"');
      }
      if (buf.length() != 0) {
        line(buf);
      }
    }
  }

  /** */
  public static void main(String... argv) throws IOException {
    if (argv.length > 2 || argv.length > 0 && !new File(argv[0]).isFile()) {
      System.err.println("Expected infile.js outfile.java");
      System.err.println();
      System.err.println(
          "Converts canned.js to a serialized "
          + HtmlElementTables.class.getName());
      System.exit(1);
    }

    String infile = argv.length >= 1 ? argv[0] : "canned-data.json";
    String outfile = argv.length >= 2
        ? argv[1] : "target/HtmlElementTablesCanned.java";

    JsonObject obj;
    FileInputStream in = new FileInputStream(infile);
    try {
      JsonReader reader = Json.createReader(in);
      try {
        obj = reader.readObject();
      } finally {
        reader.close();
      }
    } finally {
      in.close();
    }

    SourceLineWriter src = new SourceLineWriter();
    src.lines(
        "package org.owasp.html;",
        "",
        "/** Generated by " + JsonToSerializedHtmlElementTables.class + " */",
        "final class HtmlElementTablesCanned {",
        "static final HtmlElementTables TABLES;",
        "static {"
        );

    HtmlElementTables.HtmlElementNames elementNames;
    String[] elementNamesArr;
    {
      ImmutableList.Builder<String> b = ImmutableList.builder();
      JsonArray arr = obj.getJsonArray("elementNames");
      for (int i = 0, n = arr.size(); i < n; ++i) {
        b.add(arr.getString(i));
      }
      ImmutableList<String> elementNameList = b.build();
      elementNames = new HtmlElementTables.HtmlElementNames(elementNameList);
      elementNamesArr = elementNameList.toArray(new String[0]);
    }
    src.lines(
        "HtmlElementTables.HtmlElementNames elementNames",
        "= new HtmlElementTables.HtmlElementNames(");
    src.write(elementNamesArr);
    src.line(");");

    newDenseElementBinaryMatrix(
        elementNames, obj.getJsonObject("canContain"),
        "canContain", src);
    newDenseElementBinaryMatrix(
        elementNames, obj.getJsonObject("closedOnClose"),
        "closedOnClose", src);
    newDenseElementBinaryMatrix(
        elementNames, obj.getJsonObject("closedOnOpen"),
        "closedOnOpen", src);
    newSparseElementToElements(
        elementNames, obj.getJsonObject("explicitClosers"),
        "explicitClosers", src);
    newSparseElementMultitable(
        elementNames, obj.getJsonObject("impliedElements"),
        "impliedElements", src);
    newTextContentModel(
        elementNames, obj.getJsonObject("textContentModel"),
        "textContentModel", src);
    newDenseElementSet(elementNames, obj.getJsonObject("resumable"),
        "resumable", src);

    src.lines(
        "TABLES = new HtmlElementTables(",
        "elementNames,",
        "canContain,",
        "closedOnClose,",
        "closedOnOpen,",
        "explicitClosers,",
        "impliedElements,",
        "textContentModel,",
        "resumable);");

    src.lines("}", "}");

    OutputStream out = new FileOutputStream(outfile);
    try {
      OutputStreamWriter w = new OutputStreamWriter(out, "UTF-8");
      try {
        w.write(src.getSource());
      } finally {
        w.close();
      }
    } finally {
      out.close();
    }
  }

  private static void newTextContentModel(
      HtmlElementNames elementNames, JsonObject tcmObj, String fieldName,
      SourceLineWriter src) {
    byte[] packedBits = new byte[elementNames.canonNames.size()];
    for (String key : tcmObj.keySet()) {
      int ei = elementNames.getElementNameIndex(key);
      byte b = 0;
      JsonObject bitsObj = tcmObj.getJsonObject(key);
      for (String bitKey : bitsObj.keySet()) {
        HtmlElementTables.TextContentModelBit mbit = MODEL_BITS.get(bitKey);
        if (bitsObj.getBoolean(bitKey)) {
          b |= mbit.bitMask;
        } else {
          b &= ~mbit.bitMask;
        }
      }
      packedBits[ei] = b;
    }
    src.lines(
        "HtmlElementTables.TextContentModel " + fieldName + " = new "
        + "HtmlElementTables.TextContentModel(");
    src.write(packedBits);
    src.line(");");
  }

  private static void newDenseElementBinaryMatrix(
      HtmlElementTables.HtmlElementNames en,
      JsonObject obj,
      String fieldName,
      SourceLineWriter src) {
    int dim = en.canonNames.size();
    boolean[] bits = new boolean[dim * dim];
    for (String elname : obj.keySet()) {
      int ai = en.getElementNameIndex(elname);
      JsonArray arr = obj.getJsonArray(elname);
      for (int i = 0, n = arr.size(); i < n; ++i) {
        int bi = en.getElementNameIndex(arr.getString(i));
        bits[ai * dim + bi] = true;
      }
    }
    src.lines(
        "HtmlElementTables.DenseElementBinaryMatrix " + fieldName
        + " = new HtmlElementTables.DenseElementBinaryMatrix(");
    src.writePacked(bits);
    src.line(", " + dim + ");");
  }

  private static void newDenseElementSet(
      HtmlElementTables.HtmlElementNames en,
      JsonObject obj,
      String fieldName,
      SourceLineWriter src) {
    int dim = en.canonNames.size();
    boolean[] bits = new boolean[dim];
    for (String elname : obj.keySet()) {
      int i = en.getElementNameIndex(elname);
      bits[i] = obj.getBoolean(elname);
    }
    src.lines(
        "HtmlElementTables.DenseElementSet " + fieldName + " = new "
        + "HtmlElementTables.DenseElementSet("
        );
    src.writePacked(bits);
    src.lines(");");
  }

  private static void newSparseElementToElements(
      HtmlElementTables.HtmlElementNames en,
      JsonObject obj,
      String fieldName,
      SourceLineWriter src) {
    List<int[]> arrs = Lists.newArrayList();
    for (String elname : obj.keySet()) {
      int ei = en.getElementNameIndex(elname);
      ImmutableSet.Builder<String> names = ImmutableSet.builder();
      JsonArray arr = obj.getJsonArray(elname);
      for (int i = 0, n = arr.size(); i < n; ++i) {
        names.add(arr.getString(i));
      }
      ImmutableSet<String> iset = names.build();
      int[] vals = new int[iset.size()];
      int i = 0;
      for (String name : iset) {
        vals[i++] = en.getElementNameIndex(name);
      }
      Preconditions.checkState(vals.length == i);
      Arrays.sort(vals);

      int[] ints = new int[vals.length + 1];
      ints[0] = ei;
      System.arraycopy(vals, 0, ints, 1, vals.length);
      arrs.add(ints);
    }
    Collections.sort(arrs, new Comparator<int[]>() {
      public int compare(int[] a, int[] b) {
        return Integer.compare(a[0], b[0]);
      }
    });
    int[][] arr = arrs.toArray(new int[arrs.size()][]);
    src.lines(
        "HtmlElementTables.SparseElementToElements " + fieldName
        + " = new HtmlElementTables.SparseElementToElements(");
    src.write(arr);
    src.line(");");
  }

  private static void newSparseElementMultitable(
      HtmlElementTables.HtmlElementNames en,
      JsonObject obj,
      String fieldName,
      SourceLineWriter src) {
    int dim = en.canonNames.size();
    int[][][] arrs = new int[dim][][];

    for (String elname : obj.keySet()) {
      int ei = en.getElementNameIndex(elname);
      JsonObject subtable = obj.getJsonObject(elname);
      int[][] tableArr = new int[subtable.size()][];
      arrs[ei] =  tableArr;
      int ti = 0;
      for (String elnameb : subtable.keySet()) {
        JsonArray els = subtable.getJsonArray(elnameb);
        int[] row = new int[els.size() + 1];
        row[0] = en.getElementNameIndex(elnameb);
        for (int i = 0, n = els.size(); i < n; ++i) {
          row[i + 1] = en.getElementNameIndex(els.getString(i));
        }
        tableArr[ti++] = row;
      }

      Arrays.sort(tableArr, new Comparator<int[]>() {

        public int compare(int[] o1, int[] o2) {
          return o1[0] - o2[0];
        }

      });
    }
    src.lines(
        "HtmlElementTables.SparseElementMultitable " + fieldName + " = " +
        "new HtmlElementTables.SparseElementMultitable(");
    src.write(arrs);
    src.line(");");
  }

  private static final
  ImmutableMap<String, HtmlElementTables.TextContentModelBit> MODEL_BITS =
      ImmutableMap.<String, HtmlElementTables.TextContentModelBit>builder()
      .put("comments", HtmlElementTables.TextContentModelBit.COMMENTS)
      .put("entities", HtmlElementTables.TextContentModelBit.ENTITIES)
      .put("raw", HtmlElementTables.TextContentModelBit.RAW)
      .put("text", HtmlElementTables.TextContentModelBit.TEXT)
      .put("plain_text", HtmlElementTables.TextContentModelBit.PLAIN_TEXT)
      .put("unended", HtmlElementTables.TextContentModelBit.UNENDED)
      .build();
}
