package org.haox.asn1;

import org.haox.asn1.type.Asn1AppSpecific;
import org.haox.asn1.type.Asn1Tagged;
import org.haox.asn1.type.Asn1VisibleString;
import org.junit.Assert;
import org.junit.Test;

/**
Ref. X.690-0207 8.14 Encoding of a tagged value
 EXAMPLE
 With ASN.1 type definitions (in an explicit tagging environment) of:
 Type1 ::= VisibleString
 Type2 ::= [APPLICATION 3] IMPLICIT Type1
 Type3 ::= [2] Type2
 Type4 ::= [APPLICATION 7] IMPLICIT Type3
 Type5 ::= [2] IMPLICIT Type2
 a value of:
 "Jones"
 is encoded as follows:
 For Type1:
 VisibleString Length Contents
 1A16 0516 4A6F6E657316
 For Type2:
 [Application 3] Length Contents
 4316 0516 4A6F6E657316
 For Type3:
 [2] Length Contents
 A216 0716
 [APPLICATION 3] Length Contents
 4316 0516 4A6F6E657316
 For Type4:
 [Application 7] Length Contents
 6716 0716
 [APPLICATION 3] Length Contents
 4316 0516 4A6F6E657316
 For Type5:
 [2] Length Contents
 8216 0516 4A6F6E657316
 */

public class TestEncoding {
    static final String TEST_STRING = "Jones";

    static class Type1 extends Asn1VisibleString {
        Type1(String value) {
            super(value);
        }
    }

    static class Type2 extends Asn1AppSpecific {
        Type2(Type1 value) {
            super(3, value);
        }
    }

    static class Type3 extends Asn1Tagged {
        Type3(Type2 value) {
            super(2, value);
        }
    }

    static class Type4 extends Asn1AppSpecific {
        Type4(Type3 value) {
            super(7, value);
        }
    }

    static class Type5 extends Asn1Tagged {
        Type5(Type2 value) {
            super(2, value);
        }
    }

    @Test
    public void testEncodings() {
        byte[] TYPE1_EXPECTED_BYTES = new byte[] {0x1A, 0x05, 0x4A, 0x6F, 0x6E, 0x65, 0x73};
        byte[] TYPE2_EXPECTED_BYTES = new byte[] {0x43, 0x05, 0x4A, 0x6F, 0x6E, 0x65, 0x73};
        byte[] TYPE3_EXPECTED_BYTES = new byte[] {(byte) 0xA2, 0x07, 0x43, 0x05, 0x4A, 0x6F, 0x6E, 0x65, 0x73};
        byte[] TYPE4_EXPECTED_BYTES = new byte[] {(byte) 0x67, 0x07, 0x43, 0x05, 0x4A, 0x6F, 0x6E, 0x65, 0x73};
        byte[] TYPE5_EXPECTED_BYTES = new byte[] {(byte) 0x82, 0x05, 0x4A, 0x6F, 0x6E, 0x65, 0x73};

        Type1 aType1 = new Type1(TEST_STRING);
        Type2 aType2 = new Type2(aType1);
        Type3 aType3 = new Type3(aType2);
        Type4 aType4 = new Type4(aType3);
        Type5 aType5 = new Type5(aType2);

        Assert.assertArrayEquals(aType1.encode(), TYPE1_EXPECTED_BYTES);
        Assert.assertArrayEquals(aType2.encode(), TYPE2_EXPECTED_BYTES);
        //Assert.assertArrayEquals(aType3.encode(), TYPE3_EXPECTED_BYTES);
        //Assert.assertArrayEquals(aType4.encode(), TYPE4_EXPECTED_BYTES);
        //Assert.assertArrayEquals(aType5.encode(), TYPE5_EXPECTED_BYTES);
    }
}
