package org.owasp.html.empiricism;

import org.owasp.html.HtmlElementTables;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
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

  /** */
  public static void main(String... argv) throws IOException {
    if (argv.length > 2 || argv.length > 0 && !new File(argv[0]).isFile()) {
      System.err.println("Expected infile.js outfile.ser");
      System.err.println();
      System.err.println(
          "Converts canned.js to a serialized "
          + HtmlElementTables.class.getName());
      System.exit(1);
    }

    String infile = argv.length >= 1 ? argv[0] : "canned-data.json";
    String outfile = argv.length >= 2 ? argv[1] : "html-metadata.ser";

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

    HtmlElementTables.HtmlElementNames elementNames;
    {
      ImmutableList.Builder<String> b = ImmutableList.builder();
      JsonArray arr = obj.getJsonArray("elementNames");
      for (int i = 0, n = arr.size(); i < n; ++i) {
        b.add(arr.getString(i));
      }
      elementNames = new HtmlElementTables.HtmlElementNames(b.build());
    }

    HtmlElementTables.DenseElementBinaryMatrix canContain =
        newDenseElementBinaryMatrix(
            elementNames, obj.getJsonObject("canContain"));
    HtmlElementTables.DenseElementBinaryMatrix closedOnClose =
        newDenseElementBinaryMatrix(
            elementNames, obj.getJsonObject("closedOnClose"));
    HtmlElementTables.DenseElementBinaryMatrix closedOnOpen =
        newDenseElementBinaryMatrix(
            elementNames, obj.getJsonObject("closedOnOpen"));
    HtmlElementTables.SparseElementToElements explicitClosers =
        newSparseElementToElements(
            elementNames, obj.getJsonObject("explicitClosers"));
    HtmlElementTables.SparseElementMultitable impliedElements =
        newSparseElementMultitable(
            elementNames, obj.getJsonObject("impliedElements"));
    HtmlElementTables.TextContentModel textContentModel;
    {
      byte[] packedBits = new byte[elementNames.canonNames.size()];
      JsonObject tcmObj = obj.getJsonObject("textContentModel");
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
      textContentModel = new HtmlElementTables.TextContentModel(packedBits);
    }
    HtmlElementTables.DenseElementSet resumable =
        newDenseElementSet(elementNames, obj.getJsonObject("resumable"));

    HtmlElementTables tables = new HtmlElementTables(
        elementNames,
        canContain,
        closedOnClose,
        closedOnOpen,
        explicitClosers,
        impliedElements,
        textContentModel,
        resumable);
    OutputStream out = new FileOutputStream(outfile);
    try {
      ObjectOutputStream oout = new ObjectOutputStream(out);
      try {
        oout.writeObject(tables);
      } finally {
        oout.close();
      }
    } finally {
      out.close();
    }
  }

  private static HtmlElementTables.DenseElementBinaryMatrix
      newDenseElementBinaryMatrix(
          HtmlElementTables.HtmlElementNames en,
          JsonObject obj) {
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
    return new HtmlElementTables.DenseElementBinaryMatrix(bits, dim);
  }

  private static HtmlElementTables.DenseElementSet
      newDenseElementSet(
          HtmlElementTables.HtmlElementNames en,
          JsonObject obj) {
    int dim = en.canonNames.size();
    boolean[] bits = new boolean[dim];
    for (String elname : obj.keySet()) {
      int i = en.getElementNameIndex(elname);
      bits[i] = obj.getBoolean(elname);
    }
    return new HtmlElementTables.DenseElementSet(bits);
  }

  private static HtmlElementTables.SparseElementToElements
      newSparseElementToElements(
          HtmlElementTables.HtmlElementNames en,
          JsonObject obj) {
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
    return new HtmlElementTables.SparseElementToElements(
        arrs.toArray(new int[arrs.size()][]));
  }

  private static HtmlElementTables.SparseElementMultitable
      newSparseElementMultitable(
          HtmlElementTables.HtmlElementNames en,
          JsonObject obj) {
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
    return new HtmlElementTables.SparseElementMultitable(arrs);
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
