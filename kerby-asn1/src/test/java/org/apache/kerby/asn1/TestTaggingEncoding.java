/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.asn1;

import org.apache.kerby.asn1.type.Asn1Tagging;
import org.apache.kerby.asn1.type.Asn1VisibleString;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

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

public class TestTaggingEncoding {
    static final String TEST_STRING = "Jones";
    static byte[] TYPE1_EXPECTED_BYTES = new byte[] {(byte) 0x1A, (byte) 0x05, (byte) 0x4A, (byte) 0x6F, (byte) 0x6E, (byte) 0x65, (byte) 0x73};
    static byte[] TYPE2_EXPECTED_BYTES = new byte[] {(byte) 0x43, (byte) 0x05, (byte) 0x4A, (byte) 0x6F, (byte) 0x6E, (byte) 0x65, (byte) 0x73};
    static byte[] TYPE3_EXPECTED_BYTES = new byte[] {(byte) 0xA2, (byte) 0x07, (byte) 0x43, (byte) 0x05, (byte) 0x4A, (byte) 0x6F, (byte) 0x6E, (byte) 0x65, (byte) 0x73};
    static byte[] TYPE4_EXPECTED_BYTES = new byte[] {(byte) 0x67, (byte) 0x07, (byte) 0x43, (byte) 0x05, (byte) 0x4A, (byte) 0x6F, (byte) 0x6E, (byte) 0x65, (byte) 0x73};
    static byte[] TYPE5_EXPECTED_BYTES = new byte[] {(byte) 0x82, (byte) 0x05, (byte) 0x4A, (byte) 0x6F, (byte) 0x6E, (byte) 0x65, (byte) 0x73};


    public static class Type1 extends Asn1VisibleString {
        public Type1(String value) {
            super(value);
        }
        public Type1() {
            this(null);
        }
    }

    public static class Type2 extends Asn1Tagging<Type1> {
        public Type2(Type1 value) {
            super(3, value, true);
            setEncodingOption(EncodingOption.IMPLICIT);
        }
        public Type2() {
            this(null);
        }
    }

    public static class Type3 extends Asn1Tagging<Type2> {
        public Type3(Type2 value) {
            super(2, value, false);
            setEncodingOption(EncodingOption.EXPLICIT);
        }
        public Type3() {
            this(null);
        }
    }

    public static class Type4 extends Asn1Tagging<Type3> {
        public Type4(Type3 value) {
            super(7, value, true);
            setEncodingOption(EncodingOption.IMPLICIT);
        }
        public Type4() {
            this(null);
        }
    }

    public static class Type5 extends Asn1Tagging<Type2> {
        public Type5(Type2 value) {
            super(2, value, false);
            setEncodingOption(EncodingOption.IMPLICIT);
        }
        public Type5() {
            this(null);
        }
    }

    @Test
    public void testAsn1TaggingEncoding() {
        Type1 aType1 = new Type1(TEST_STRING);
        Type2 aType2 = new Type2(aType1);
        Type3 aType3 = new Type3(aType2);
        Type4 aType4 = new Type4(aType3);
        Type5 aType5 = new Type5(aType2);

        Assert.assertArrayEquals(TYPE1_EXPECTED_BYTES, aType1.encode());
        Assert.assertArrayEquals(TYPE2_EXPECTED_BYTES, aType2.encode());
        Assert.assertArrayEquals(TYPE3_EXPECTED_BYTES, aType3.encode());
        Assert.assertArrayEquals(TYPE4_EXPECTED_BYTES, aType4.encode());
        Assert.assertArrayEquals(TYPE5_EXPECTED_BYTES, aType5.encode());
    }

    @Test
    public void testAsn1TaggingDecoding() throws IOException {
        Type1 aType1 = new Type1();
        aType1.decode(TYPE1_EXPECTED_BYTES);
        Assert.assertEquals(TEST_STRING, aType1.getValue());

        Type2 aType2 = new Type2();
        aType2.decode(TYPE2_EXPECTED_BYTES);
        Assert.assertEquals(TEST_STRING, aType2.getValue().getValue());

        Type3 aType3 = new Type3();
        aType3.decode(TYPE3_EXPECTED_BYTES);
        Assert.assertEquals(TEST_STRING, aType3.getValue().getValue().getValue());

        Type4 aType4 = new Type4();
        aType4.decode(TYPE4_EXPECTED_BYTES);
        Assert.assertEquals(TEST_STRING, aType4.getValue().getValue().getValue().getValue());

        Type5 aType5 = new Type5();
        aType5.decode(TYPE5_EXPECTED_BYTES);
        Assert.assertEquals(TEST_STRING, aType5.getValue().getValue().getValue());
    }

    @Test
    public void testTaggingEncodingOption() {
        Type1 aType1 = new Type1(TEST_STRING);
        Type2 aType2 = new Type2(aType1);
        Type3 aType3 = new Type3(aType2);
        Type4 aType4 = new Type4(aType3);
        Type5 aType5 = new Type5(aType2);

        Assert.assertArrayEquals(TYPE1_EXPECTED_BYTES, aType1.encode());
        Assert.assertArrayEquals(TYPE2_EXPECTED_BYTES,
                aType1.taggedEncode(TaggingOption.newImplicitAppSpecific(3))); // for Type2
        Assert.assertArrayEquals(TYPE3_EXPECTED_BYTES,
                aType2.taggedEncode(TaggingOption.newExplicitContextSpecific(2))); // for Type3
        Assert.assertArrayEquals(TYPE4_EXPECTED_BYTES,
                aType3.taggedEncode(TaggingOption.newImplicitAppSpecific(7))); // for Type4
        Assert.assertArrayEquals(TYPE5_EXPECTED_BYTES,
                aType2.taggedEncode(TaggingOption.newImplicitContextSpecific(2)));  // for Type5
    }

    @Test
    public void testTaggingDecodingOption() throws IOException {
        Type1 aType1 = new Type1();
        aType1.decode(TYPE1_EXPECTED_BYTES);
        Assert.assertEquals(TEST_STRING, aType1.getValue());

        // for Type2
        aType1 = new Type1();
        aType1.taggedDecode(TYPE2_EXPECTED_BYTES, TaggingOption.newImplicitAppSpecific(3));
        Assert.assertEquals(TEST_STRING, aType1.getValue());

        // for Type3
        Type2 aType2 = new Type2();
        aType2.taggedDecode(TYPE3_EXPECTED_BYTES, TaggingOption.newExplicitContextSpecific(2));
        Assert.assertEquals(TEST_STRING, aType2.getValue().getValue());

        // for Type4
        Type3 aType3 = new Type3();
        aType3.taggedDecode(TYPE4_EXPECTED_BYTES, TaggingOption.newImplicitAppSpecific(7));
        Assert.assertEquals(TEST_STRING, aType3.getValue().getValue().getValue());

        // for Type5
        aType2 = new Type2();
        aType2.taggedDecode(TYPE5_EXPECTED_BYTES, TaggingOption.newImplicitContextSpecific(2));
        Assert.assertEquals(TEST_STRING, aType2.getValue().getValue());
    }
}
