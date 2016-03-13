package com.google.security.fences.policy;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public final class ApiElementTest extends TestCase {

  public static final void testToInternalName() {
    assertEquals(
        "", ApiElement.DEFAULT_PACKAGE.toInternalName());

    ApiElement com = ApiElement.DEFAULT_PACKAGE
        .child("com", ApiElementType.PACKAGE);
    ApiElement comExample = com
        .child("example", ApiElementType.PACKAGE);
    ApiElement comExampleFoo = comExample
        .child("Foo", ApiElementType.CLASS);
    ApiElement comExampleFooBar = comExampleFoo
        .child("Bar", ApiElementType.CLASS);
    ApiElement comExampleFooBarX = comExampleFooBar
        .child("x", ApiElementType.FIELD);
    ApiElement comExampleFooBarF = comExampleFooBar
        .child("f", ApiElementType.METHOD);
    ApiElement comExampleFooBarCtor = comExampleFooBar
        .child(ApiElement.CONSTRUCTOR_SPECIAL_METHOD_NAME,
               ApiElementType.CONSTRUCTOR);

    assertEquals("com/", com.toInternalName());
    assertEquals("com/example/", comExample.toInternalName());
    assertEquals("com/example/Foo", comExampleFoo.toInternalName());
    assertEquals("com/example/Foo$Bar", comExampleFooBar.toInternalName());
    assertEquals("com/example/Foo$Bar#x", comExampleFooBarX.toInternalName());
    assertEquals("com/example/Foo$Bar#f", comExampleFooBarF.toInternalName());
    assertEquals("com/example/Foo$Bar#<init>",
                 comExampleFooBarCtor.toInternalName());
  }
}
