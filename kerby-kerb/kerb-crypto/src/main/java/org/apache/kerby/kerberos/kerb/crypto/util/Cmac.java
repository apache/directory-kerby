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
package org.apache.kerby.kerberos.kerb.crypto.util;

import org.apache.kerby.kerberos.kerb.crypto.enc.EncryptProvider;
import org.apache.kerby.kerberos.kerb.KrbException;

import java.util.Arrays;

/**
 * Based on MIT krb5 cmac.c
 */
public class Cmac {

    private static byte[] constRb = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0x87
    };

    public static byte[] cmac(EncryptProvider encProvider, byte[] key,
                       byte[] data, int outputSize) throws KrbException {
        return cmac(encProvider, key, data, 0, data.length, outputSize);
    }

    public static byte[] cmac(EncryptProvider encProvider, byte[] key, byte[] data,
                       int start, int len, int outputSize) throws KrbException {
        byte[] hash = Cmac.cmac(encProvider, key, data, start, len);
        if (hash.length > outputSize) {
            byte[] output = new byte[outputSize];
            System.arraycopy(hash, 0, output, 0, outputSize);
            return output;
        } else {
            return hash;
        }
    }

    public static byte[] cmac(EncryptProvider encProvider,
                              byte[] key, byte[] data) throws KrbException {
        return cmac(encProvider, key, data, 0, data.length);
    }

    public static byte[] cmac(EncryptProvider encProvider,
                              byte[] key, byte[] data, int start, int len) throws KrbException {

        int blockSize = encProvider.blockSize();

        byte[] Y = new byte[blockSize];
        byte[] mLast = new byte[blockSize];
        byte[] padded = new byte[blockSize];
        byte[] K1 = new byte[blockSize];
        byte[] K2 = new byte[blockSize];

        // step 1
        makeSubkey(encProvider, key, K1, K2);

        // step 2
        int n = (len + blockSize - 1) / blockSize;

        // step 3
        boolean lastIsComplete;
        if (n == 0) {
            n = 1;
            lastIsComplete = false;
        } else {
            lastIsComplete = ((len % blockSize) == 0);
        }

        // Step 6 (all but last block)
        byte[] cipherState = new byte[blockSize];
        byte[] cipher = new byte[blockSize];
        for (int i = 0; i < n - 1; i++) {
            System.arraycopy(data, i * blockSize, cipher, 0, blockSize);
            encryptBlock(encProvider, key, cipherState, cipher);
            System.arraycopy(cipher, 0, cipherState, 0, blockSize);
        }

        // step 5
        System.arraycopy(cipher, 0, Y, 0, blockSize);

        // step 4
        int lastPos = (n - 1) * blockSize;
        int lastLen = lastIsComplete ? blockSize : len % blockSize;
        byte[] lastBlock = new byte[lastLen];
        System.arraycopy(data, lastPos, lastBlock, 0, lastLen);
        if (lastIsComplete) {
            BytesUtil.xor(lastBlock, K1, mLast);
        } else {
            padding(lastBlock, padded);
            BytesUtil.xor(padded, K2, mLast);
        }

        // Step 6 (last block)
        encryptBlock(encProvider, key, cipherState, mLast);

        return mLast;
    }

    // Generate subkeys K1 and K2 as described in RFC 4493 figure 2.2.
    private static void makeSubkey(EncryptProvider encProvider,
                              byte[] key, byte[] K1, byte[] K2) throws KrbException {

        // L := encrypt(K, const_Zero)
        byte[] L = new byte[K1.length];
        Arrays.fill(L, (byte) 0);
        encryptBlock(encProvider, key, null, L);

        // K1 := (MSB(L) == 0) ? L << 1 : (L << 1) XOR const_Rb
        if ((L[0] & 0x80) == 0) {
            leftShiftByOne(L, K1);
        } else {
            byte[] tmp = new byte[K1.length];
            leftShiftByOne(L, tmp);
            BytesUtil.xor(tmp, constRb, K1);
        }

        // K2 := (MSB(K1) == 0) ? K1 << 1 : (K1 << 1) XOR const_Rb
        if ((K1[0] & 0x80) == 0) {
            leftShiftByOne(K1, K2);
        } else {
            byte[] tmp = new byte[K1.length];
            leftShiftByOne(K1, tmp);
            BytesUtil.xor(tmp, constRb, K2);
        }
    }

    private static void encryptBlock(EncryptProvider encProvider,
                                     byte[] key, byte[] cipherState, byte[] block) throws KrbException {
        if (cipherState == null) {
            cipherState = new byte[encProvider.blockSize()];
        }
        if (encProvider.supportCbcMac()) {
            encProvider.cbcMac(key, cipherState, block);
        } else {
            encProvider.encrypt(key, cipherState, block);
        }
    }

    private static void leftShiftByOne(byte[] input, byte[] output) {
        byte overflow = 0;

        for (int i = input.length - 1; i >= 0; i--) {
            output[i] = (byte) (input[i] << 1);
            output[i] |= overflow;
            overflow = (byte) ((input[i] & 0x80) != 0 ? 1 : 0);
        }
    }

    // Padding out data with a 1 bit followed by 0 bits, placing the result in pad
    private static void padding(byte[] data, byte[] padded) {
        int len = data.length;

        // original last block
        System.arraycopy(data, 0, padded, 0, len);

        padded[len] = (byte) 0x80;

        for (int i = len + 1; i < padded.length; i++) {
            padded[i] = 0x00;
        }
    }
}
