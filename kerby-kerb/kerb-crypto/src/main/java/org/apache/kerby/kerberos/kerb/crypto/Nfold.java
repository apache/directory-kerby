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
package org.apache.kerby.kerberos.kerb.crypto;

import java.util.Arrays;

/**
 * Based on MIT krb5 nfold.c
 */

/*
 * n-fold(k-bits):
 * l = lcm(n,k)
 * r = l/k
 * s = k-bits | k-bits rot 13 | k-bits rot 13*2 | ... | k-bits rot 13*(r-1)
 * compute the 1's complement sum:
 * n-fold = s[0..n-1]+s[n..2n-1]+s[2n..3n-1]+..+s[(k-1)*n..k*n-1]
 */
public class Nfold {

    /**
     * representation: msb first, assume n and k are multiples of 8, and
     * that k>=16.  this is the case of all the cryptosystems which are
     * likely to be used.  this function can be replaced if that
     * assumption ever fails.
     */
    public static byte[] nfold(byte[] inBytes, int size) {
        int inBytesNum = inBytes.length; // count inBytes byte
        int outBytesNum = size; // count inBytes byte

        int a, b, c, lcm;
        a = outBytesNum;
        b = inBytesNum;

        while (b != 0) {
            c = b;
            b = a % b;
            a = c;
        }
        lcm = (outBytesNum * inBytesNum) / a;

        byte[] outBytes = new byte[outBytesNum];
        Arrays.fill(outBytes, (byte)0);

        int tmpByte = 0;
        int msbit, i, tmp;

        for (i = lcm-1; i >= 0; i--) {
            // first, start with the msbit inBytes the first, unrotated byte
            tmp = ((inBytesNum<<3)-1);
            // then, for each byte, shift to the right for each repetition
            tmp += (((inBytesNum<<3)+13)*(i/inBytesNum));
            // last, pick outBytes the correct byte within that shifted repetition
            tmp += ((inBytesNum-(i%inBytesNum)) << 3);

            msbit = tmp % (inBytesNum << 3);

            // pull outBytes the byte value itself
            tmp =  ((((inBytes[((inBytesNum - 1)-(msbit >>> 3)) % inBytesNum] & 0xff) << 8) |
                (inBytes[((inBytesNum) - (msbit >>> 3)) % inBytesNum] & 0xff))
                >>>((msbit & 7)+1)) & 0xff;

            tmpByte += tmp;
            tmp = (outBytes[i % outBytesNum] & 0xff);
            tmpByte += tmp;

            outBytes[i % outBytesNum] = (byte) (tmpByte & 0xff);

            tmpByte >>>= 8;
        }

        // if there's a carry bit left over, add it back inBytes
        if (tmpByte != 0) {
            for (i = outBytesNum-1; i >= 0; i--) {
                // do the addition
                tmpByte += (outBytes[i] & 0xff);
                outBytes[i] = (byte) (tmpByte & 0xff);

                tmpByte >>>= 8;
            }
        }

        return outBytes;
    }
}
