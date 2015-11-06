package org.apache.kerby.kerberos.kerb.spec.base;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.apache.kerby.kerberos.kerb.spec.KrbEnum;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class KrbFlagsTest {
  
  public static final int FLAG_0 = 0b00000000000000000000000000000001;
  public static final int FLAG_1 = 0b00000000000000000000000000000010;
  public static final int FLAG_2 = 0x00000004;
  public static final int FLAG_3 = 0x00000008;
  public static final int FLAG_4 = 16;
  public static final int FLAG_5 = 32;
  
  public enum TestEnum implements KrbEnum {
    FLAG_0(0x00000001),
    FLAG_1(0x00000002),
    FLAG_2(0x00000004),
    FLAG_3(0x00000008),
    FLAG_4(0x00000010),
    FLAG_5(0x00000020);
    
    private int value;
    
    private TestEnum(int value) {
      this.value = value;
    }

    @Override
    public int getValue() {
      return value;
    }
    
  }
  
  @Rule
  public ExpectedException thrown = ExpectedException.none();
  
  private KrbFlags krbFlags;
  
  @Before
  public void setUp() {
    krbFlags = new KrbFlags(FLAG_5 | FLAG_3 | FLAG_1);
  }

  @Test
  @Ignore
  public void testToValue() throws IOException {
    byte[] value = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};
    krbFlags.setValue(value);
    krbFlags.toValue();
    assertEquals(0b11011110101011011011111011101111, krbFlags.getFlags());
  }

  @Test
  public void testKrbFlags() {
    krbFlags = new KrbFlags();
    assertEquals(0b00000000000000000000000000000000, krbFlags.getFlags());
  }

  @Test
  public void testKrbFlagsInt() {
    krbFlags = new KrbFlags(FLAG_4 | FLAG_2 | FLAG_0);
    assertEquals(0b00000000000000000000000000010101, krbFlags.getFlags());
  }

  @Test
  public void testSetFlags() {
    krbFlags.setFlags(FLAG_4 | FLAG_2 | FLAG_0);
    assertEquals(0b00000000000000000000000000010101, krbFlags.getFlags());
  }

  @Test
  public void testGetFlags() {
    assertEquals(0b00000000000000000000000000101010, krbFlags.getFlags());
  }

  @Test
  public void testIsFlagSetInt() {
    assertTrue(krbFlags.isFlagSet(FLAG_5));
    assertFalse(krbFlags.isFlagSet(FLAG_4));
  }

  @Test
  public void testSetFlagInt() {
    krbFlags.setFlag(FLAG_4);
    assertEquals(0b00000000000000000000000000111010, krbFlags.getFlags());
  }

  @Test
  public void testClearFlagInt() {
    krbFlags.clearFlag(FLAG_3);
    assertEquals(0b00000000000000000000000000100010, krbFlags.getFlags());
  }

  @Test
  public void testClear() {
    krbFlags.clear();
    assertEquals(0b00000000000000000000000000000000, krbFlags.getFlags());
  }

  @Test
  public void testIsFlagSetKrbEnum() {
    assertTrue(krbFlags.isFlagSet(TestEnum.FLAG_5));
    assertFalse(krbFlags.isFlagSet(TestEnum.FLAG_4));
  }

  @Test
  public void testSetFlagKrbEnum() {
    krbFlags.setFlag(TestEnum.FLAG_4);
    assertEquals(0b00000000000000000000000000111010, krbFlags.getFlags());
  }

  @Test
  public void testSetFlagKrbEnumBoolean() {
    krbFlags.setFlag(TestEnum.FLAG_4, true);
    assertEquals(0b00000000000000000000000000111010, krbFlags.getFlags());
    krbFlags.setFlag(TestEnum.FLAG_4, false);
    assertEquals(0b00000000000000000000000000101010, krbFlags.getFlags());
  }

  @Test
  public void testClearFlagKrbEnum() {
    krbFlags.clearFlag(TestEnum.FLAG_3);
    assertEquals(0b00000000000000000000000000100010, krbFlags.getFlags());
  }

}
