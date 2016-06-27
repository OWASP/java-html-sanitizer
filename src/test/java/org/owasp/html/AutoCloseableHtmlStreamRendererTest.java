package org.owasp.html;

import java.io.Closeable;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.IdentityHashMap;
import java.util.Map;

import org.junit.Test;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public class AutoCloseableHtmlStreamRendererTest extends TestCase {

  static final class SimpleCloseable implements Closeable {
    boolean closed;

    public void close() throws IOException {
      this.closed = true;
    }
  }


  @Test
  public static void testThatCloseablesAreClosed() throws IOException {
    @SuppressWarnings("resource")
    SimpleCloseable closeable = new SimpleCloseable();

    assertFalse(closeable.closed);

    assertTrue(AutoCloseableHtmlStreamRenderer.isAutoCloseable(closeable));

    assertFalse(closeable.closed);

    AutoCloseableHtmlStreamRenderer.closeIfAnyCloseable(closeable);

    assertTrue(closeable.closed);
  }

  @Test
  public static void testThatAutoCloseablesAreClosed() throws IOException {
    // We need a way to create an AutoCloseable instance that we can compile.
    // JDK6 so that our tests are portable.
    Class<?> autoCloseableClass;
    try {
      autoCloseableClass = Class.forName("java.lang.AutoCloseable");
    } catch (@SuppressWarnings("unused") ClassNotFoundException ex) {
      // OK on JDK 6.
      return;
    }

    final Map<Object, Boolean> closed = new IdentityHashMap<Object, Boolean>();

    Object autoCloseableProxyInstance = Proxy.newProxyInstance(
        autoCloseableClass.getClassLoader(),
        new Class<?>[] { autoCloseableClass },
        new InvocationHandler() {
          public Object invoke(Object proxy, Method method, Object[] args)
          throws Throwable {
            if ("close".equals(method.getName())) {
              assertTrue(args == null || args.length == 0);
              closed.put(proxy, true);
              return null;
            } else {
              return method.invoke(new Object());
            }
          }
        });

    assertTrue(
        AutoCloseableHtmlStreamRenderer.isAutoCloseable(
            autoCloseableProxyInstance));

    assertFalse(closed.containsKey(autoCloseableProxyInstance));

    AutoCloseableHtmlStreamRenderer.closeIfAnyCloseable(
        autoCloseableProxyInstance);

    assertTrue(closed.containsKey(autoCloseableProxyInstance));
  }

}
