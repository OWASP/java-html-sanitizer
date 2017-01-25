package org.owasp.html;

import com.google.common.base.Preconditions;

final class IntVector {
  private int[] contents = ZERO_INTS;
  private int left, size;

  private static final int[] ZERO_INTS = new int[0];

  public int size() {
    return size;
  }

  public boolean isEmpty() {
    return size == 0;
  }

  public int get(int i) {
    return contents[(i + left) % contents.length];
  }

  private void makeSpace() {
    int bufsize = contents.length;
    if (size == bufsize) {
      int[] newContents = new int[Math.max(16, bufsize * 2)];
      for (int i = 0, k = left; i < size; ++i, ++k) {
        newContents[i] = contents[k % bufsize];
      }
      this.left = 0;
      this.contents = newContents;
    }
  }

  public void add(int value) {
    makeSpace();
    contents[(left + size) % contents.length] = value;
    ++size;
  }

  public int remove(int i) {
    Preconditions.checkArgument(0 <= i && i < size);
    int bufsize = contents.length;
    int idx = (left + i) % bufsize;
    int result = contents[idx];

    int nToShiftLeft = size - (i + 1);
    if (i == 0) {
      left = (left + 1) % bufsize;
    } else if (i + 1== size) {
      // do nothing
    } else if (idx + nToShiftLeft < bufsize) {
      // The items to shift do not wrap around the right of the buffer.
      System.arraycopy(contents, idx + 1, contents, idx, nToShiftLeft);
    } else {
      // They do.
      int itemShiftedAround = contents[0];
      int right = (left + size) % bufsize;
      Preconditions.checkState(right <= left);
      System.arraycopy(contents, 1, contents, 0, right);
      System.arraycopy(contents, idx + 1, contents, idx, bufsize - idx - 1);
      contents[bufsize - 1] = itemShiftedAround;
    }
    --size;
    return result;
  }

  public int removeLast() {
    return remove(size - 1);
  }

  public int removeFirst() {
    return remove(0);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) { return true; }
    if (!(o instanceof IntVector)) {
      return false;
    }
    IntVector that = (IntVector) o;
    if (this.size != that.size) {
      return false;
    }
    int thisBufSize = this.contents.length;
    int thatBufSize = that.contents.length;
    for (int i = this.left, j = that.left; i < size; ++i, ++j) {
      if (this.contents[i % thisBufSize] != that.contents[j % thatBufSize]) {
        return false;
      }
    }
    return true;
  }

  @Override
  public int hashCode() {
    int hc = size;
    int bufsize = contents.length;
    for (int i = 0; i < size; ++i) {
      hc = 31 * hc + contents[(i + left) % bufsize];
    }
    return hc;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append('[');
    int bufsize = contents.length;
    for (int i = 0; i < size; ++i) {
      if (i != 0) { sb.append(", "); }
      sb.append(contents[(i + left) % bufsize]);
    }
    return sb.append(']').toString();
  }

  public void clear() {
    this.left = this.size = 0;
  }

  public int getLast() {
    return get(size - 1);
  }

  public int lastIndexOf(int value) {
    if (size != 0) {
      int bufsize = contents.length;
      int pos = (left + size) % bufsize;
      do {
        --pos;
        if (pos < 0) {
          pos = bufsize - 1;
        }
        if (contents[pos] == value) {
          return (pos - left + bufsize) % bufsize;
        }
      } while (pos != left);
    }
    return -1;
  }
}
