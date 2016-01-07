/*
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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * From RFC 4556:
 *
 * Define the function octetstring2key() as follows:
 *
 * octetstring2key(x) == random-to-key(K-truncate(
 * SHA1(0x00 | x) |
 * SHA1(0x01 | x) |
 * SHA1(0x02 | x) |
 * ...
 * ))
 *
 * where x is an octet string; | is the concatenation operator; 0x00,
 * 0x01, 0x02, etc. are each represented as a single octet; random-
 * to-key() is an operation that generates a protocol key from a
 * bitstring of length K; and K-truncate truncates its input to the
 * first K bits.  Both K and random-to-key() are as defined in the
 * kcrypto profile [RFC3961] for the enctype of the AS reply key.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class OctetString2Key {
    /**
     * Performs the function K-truncate to generate the AS reply key k.
     *
     * @param k The k
     * @param x The x
     * @return The AS reply key value.
     */
    public static byte[] kTruncate(int k, byte[] x) {
        int numberOfBytes = k / 8;
        byte[] result = new byte[numberOfBytes];

        int count = 0;
        byte[] filler = calculateIntegrity((byte) count, x);

        int position = 0;

        for (int i = 0; i < numberOfBytes; i++) {
            if (position < filler.length) {
                result[i] = filler[position];
                position++;
            } else {
                count++;
                filler = calculateIntegrity((byte) count, x);
                position = 0;
                result[i] = filler[position];
                position++;
            }
        }

        return result;
    }


    private static byte[] calculateIntegrity(byte count, byte[] data) {
        try {
            MessageDigest digester = MessageDigest.getInstance("SHA1");
            digester.update(count);

            return digester.digest(data);
        } catch (NoSuchAlgorithmException nsae) {
            return new byte[0];
        }
    }
}
