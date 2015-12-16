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
package org.apache.kerby.kerberos.kerb.crypto.dh;


import java.util.Arrays;
import org.junit.Test;


/**
 * From RFC 4556:
 * <p/>
 * "Appendix B.  Test Vectors
 * <p/>
 * Function octetstring2key() is defined in Section 3.2.3.1.  This section describes
 * a few sets of test vectors that would be useful for implementers of octetstring2key()."
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class OctetString2KeyTest extends org.junit.Assert {
    /**
     * Set 1:
     * =====
     * Input octet string x is:
     * <p/>
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * <p/>
     * Output of K-truncate() when the key size is 32 octets:
     * <p/>
     * 5e e5 0d 67 5c 80 9f e5 9e 4a 77 62 c5 4b 65 83
     * 75 47 ea fb 15 9b d8 cd c7 5f fc a5 91 1e 4c 41
     */
    @Test
    public void testSet1() {
        byte[] inputOctetString = new byte[16 * 16];

        byte[] expectedOutput =
                {(byte) 0x5e, (byte) 0xe5, (byte) 0x0d, (byte) 0x67, (byte) 0x5c, (byte) 0x80, (byte) 0x9f,
                        (byte) 0xe5, (byte) 0x9e, (byte) 0x4a, (byte) 0x77, (byte) 0x62, (byte) 0xc5,
                        (byte) 0x4b, (byte) 0x65, (byte) 0x83, (byte) 0x75, (byte) 0x47, (byte) 0xea,
                        (byte) 0xfb, (byte) 0x15, (byte) 0x9b, (byte) 0xd8, (byte) 0xcd, (byte) 0xc7,
                        (byte) 0x5f, (byte) 0xfc, (byte) 0xa5, (byte) 0x91, (byte) 0x1e, (byte) 0x4c, (byte) 0x41};

        int keySize = 32 * 8;

        byte[] result = OctetString2Key.kTruncate(keySize, inputOctetString);

        assertTrue(Arrays.equals(result, expectedOutput));
    }


    /**
     * Set 2:
     * =====
     * Input octet string x is:
     * <p/>
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     * <p/>
     * Output of K-truncate() when the key size is 32 octets:
     * <p/>
     * ac f7 70 7c 08 97 3d df db 27 cd 36 14 42 cc fb
     * a3 55 c8 88 4c b4 72 f3 7d a6 36 d0 7d 56 78 7e
     */
    @Test
    public void testSet2() {
        byte[] inputOctetString = new byte[16 * 8];

        byte[] expectedOutput =
                {(byte) 0xac, (byte) 0xf7, (byte) 0x70, (byte) 0x7c, (byte) 0x08, (byte) 0x97, (byte) 0x3d,
                        (byte) 0xdf, (byte) 0xdb, (byte) 0x27, (byte) 0xcd, (byte) 0x36, (byte) 0x14,
                        (byte) 0x42, (byte) 0xcc, (byte) 0xfb, (byte) 0xa3, (byte) 0x55, (byte) 0xc8,
                        (byte) 0x88, (byte) 0x4c, (byte) 0xb4, (byte) 0x72, (byte) 0xf3, (byte) 0x7d,
                        (byte) 0xa6, (byte) 0x36, (byte) 0xd0, (byte) 0x7d, (byte) 0x56, (byte) 0x78, (byte) 0x7e};

        int keySize = 32 * 8;

        byte[] result = OctetString2Key.kTruncate(keySize, inputOctetString);

        assertTrue(Arrays.equals(result, expectedOutput));
    }


    /**
     * Set 3:
     * ======
     * Input octet string x is:
     * <p/>
     * 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
     * 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e
     * 0f 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d
     * 0e 0f 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c
     * 0d 0e 0f 10 00 01 02 03 04 05 06 07 08 09 0a 0b
     * 0c 0d 0e 0f 10 00 01 02 03 04 05 06 07 08 09 0a
     * 0b 0c 0d 0e 0f 10 00 01 02 03 04 05 06 07 08 09
     * 0a 0b 0c 0d 0e 0f 10 00 01 02 03 04 05 06 07 08
     * <p/>
     * Output of K-truncate() when the key size is 32 octets:
     * <p/>
     * c4 42 da 58 5f cb 80 e4 3b 47 94 6f 25 40 93 e3
     * 73 29 d9 90 01 38 0d b7 83 71 db 3a cf 5c 79 7e
     */
    @Test
    public void testSet3() {
        byte[] inputOctetString =
                {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,
                        (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c,
                        (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x00, (byte) 0x01,
                        (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
                        (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d,
                        (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x02,
                        (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                        (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e,
                        (byte) 0x0f, (byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
                        (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09,
                        (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f,
                        (byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                        (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a,
                        (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10,
                        (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                        (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b,
                        (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x00,
                        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,
                        (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c,
                        (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x00, (byte) 0x01,
                        (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

        byte[] expectedOutput =
                {(byte) 0xc4, (byte) 0x42, (byte) 0xda, (byte) 0x58, (byte) 0x5f, (byte) 0xcb, (byte) 0x80,
                        (byte) 0xe4, (byte) 0x3b, (byte) 0x47, (byte) 0x94, (byte) 0x6f, (byte) 0x25,
                        (byte) 0x40, (byte) 0x93, (byte) 0xe3, (byte) 0x73, (byte) 0x29, (byte) 0xd9,
                        (byte) 0x90, (byte) 0x01, (byte) 0x38, (byte) 0x0d, (byte) 0xb7, (byte) 0x83,
                        (byte) 0x71, (byte) 0xdb, (byte) 0x3a, (byte) 0xcf, (byte) 0x5c, (byte) 0x79, (byte) 0x7e};

        int keySize = 32 * 8;

        byte[] result = OctetString2Key.kTruncate(keySize, inputOctetString);

        assertTrue(Arrays.equals(result, expectedOutput));
    }


    /**
     * Set 4:
     * =====
     * Input octet string x is:
     * <p/>
     * 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
     * 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e
     * 0f 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d
     * 0e 0f 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c
     * 0d 0e 0f 10 00 01 02 03 04 05 06 07 08
     * <p/>
     * Output of K-truncate() when the key size is 32 octets:
     * <p/>
     * 00 53 95 3b 84 c8 96 f4 eb 38 5c 3f 2e 75 1c 4a
     * 59 0e d6 ff ad ca 6f f6 4f 47 eb eb 8d 78 0f fc
     */
    @Test
    public void testSet4() {
        byte[] inputOctetString =
                {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,
                        (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c,
                        (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x00, (byte) 0x01,
                        (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
                        (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d,
                        (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x02,
                        (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                        (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e,
                        (byte) 0x0f, (byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
                        (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09,
                        (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f,
                        (byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                        (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

        byte[] expectedOutput =
                {(byte) 0x00, (byte) 0x53, (byte) 0x95, (byte) 0x3b, (byte) 0x84, (byte) 0xc8, (byte) 0x96,
                        (byte) 0xf4, (byte) 0xeb, (byte) 0x38, (byte) 0x5c, (byte) 0x3f, (byte) 0x2e,
                        (byte) 0x75, (byte) 0x1c, (byte) 0x4a, (byte) 0x59, (byte) 0x0e, (byte) 0xd6,
                        (byte) 0xff, (byte) 0xad, (byte) 0xca, (byte) 0x6f, (byte) 0xf6, (byte) 0x4f,
                        (byte) 0x47, (byte) 0xeb, (byte) 0xeb, (byte) 0x8d, (byte) 0x78, (byte) 0x0f, (byte) 0xfc};

        int keySize = 32 * 8;

        byte[] result = OctetString2Key.kTruncate(keySize, inputOctetString);

        assertTrue(Arrays.equals(result, expectedOutput));
    }
}
