package org.owasp.html;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Internal helper for common Collection creation/copy methods
 */
final class CollectionsHelper {
  public static <E> List<E> copyToUnmodifiableList(Collection<? extends E> list) {
    final ArrayList<E> newList = new ArrayList<>(list.size());
    newList.addAll(list);
    return Collections.unmodifiableList(newList);
  }

  public static <E> Set<E> copyToUnmodifiableSet(Collection<? extends E> set) {
    return Collections.unmodifiableSet(new HashSet<E>(set));
  }

  public static <K, V> Map<K, V> copyToUnmodifiableMap(Map<? extends K, ? extends V> map) {
    return Collections.unmodifiableMap(new HashMap<>(map));
  }
}
