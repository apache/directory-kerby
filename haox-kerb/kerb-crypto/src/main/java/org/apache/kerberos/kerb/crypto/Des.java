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
package org.apache.kerberos.kerb.crypto;

import java.util.Arrays;

/**
 * Based on MIT krb5 weak_key.c
 */
public class Des {

    /*
     * The following are the weak DES keys:
     */
    static byte[][] WEAK_KEYS = {
    /* weak keys */
            {(byte) 0x01,(byte) 0x01,(byte) 0x01,(byte) 0x01,(byte) 0x01,(byte) 0x01,(byte) 0x01,(byte) 0x01},
            {(byte) 0xfe,(byte) 0xfe,(byte) 0xfe,(byte) 0xfe,(byte) 0xfe,(byte) 0xfe,(byte) 0xfe,(byte) 0xfe},
            {(byte) 0x1f,(byte) 0x1f,(byte) 0x1f,(byte) 0x1f,(byte) 0x0e,(byte) 0x0e,(byte) 0x0e,(byte) 0x0e},
            {(byte) 0xe0,(byte) 0xe0,(byte) 0xe0,(byte) 0xe0,(byte) 0xf1,(byte) 0xf1,(byte) 0xf1,(byte) 0xf1},

    /* semi-weak */
            {(byte) 0x01,(byte) 0xfe,(byte) 0x01,(byte) 0xfe,(byte) 0x01,(byte) 0xfe,(byte) 0x01,(byte) 0xfe},
            {(byte) 0xfe,(byte) 0x01,(byte) 0xfe,(byte) 0x01,(byte) 0xfe,(byte) 0x01,(byte) 0xfe,(byte) 0x01},

            {(byte) 0x1f,(byte) 0xe0,(byte) 0x1f,(byte) 0xe0,(byte) 0x0e,(byte) 0xf1,(byte) 0x0e,(byte) 0xf1},
            {(byte) 0xe0,(byte) 0x1f,(byte) 0xe0,(byte) 0x1f,(byte) 0xf1,(byte) 0x0e,(byte) 0xf1,(byte) 0x0e},

            {(byte) 0x01,(byte) 0xe0,(byte) 0x01,(byte) 0xe0,(byte) 0x01,(byte) 0xf1,(byte) 0x01,(byte) 0xf1},
            {(byte) 0xe0,(byte) 0x01,(byte) 0xe0,(byte) 0x01,(byte) 0xf1,(byte) 0x01,(byte) 0xf1,(byte) 0x01},

            {(byte) 0x1f,(byte) 0xfe,(byte) 0x1f,(byte) 0xfe,(byte) 0x0e,(byte) 0xfe,(byte) 0x0e,(byte) 0xfe},
            {(byte) 0xfe,(byte) 0x1f,(byte) 0xfe,(byte) 0x1f,(byte) 0xfe,(byte) 0x0e,(byte) 0xfe,(byte) 0x0e},

            {(byte) 0x01,(byte) 0x1f,(byte) 0x01,(byte) 0x1f,(byte) 0x01,(byte) 0x0e,(byte) 0x01,(byte) 0x0e},
            {(byte) 0x1f,(byte) 0x01,(byte) 0x1f,(byte) 0x01,(byte) 0x0e,(byte) 0x01,(byte) 0x0e,(byte) 0x01},

            {(byte) 0xe0,(byte) 0xfe,(byte) 0xe0,(byte) 0xfe,(byte) 0xf1,(byte) 0xfe,(byte) 0xf1,(byte) 0xfe},
            {(byte) 0xfe,(byte) 0xe0,(byte) 0xfe,(byte) 0xe0,(byte) 0xfe,(byte) 0xf1,(byte) 0xfe,(byte) 0xf1}
    };

    public static boolean isWeakKey(byte[] key, int offset, int len) {
        for (byte[] weakKey : WEAK_KEYS) {
            if (weakKey.length != len)
                return false;

            for (int i = 0; i < len; i++) {
                if (weakKey[i] != key[i]) {
                    return false;
                }
            }
        }
        return false;
    }

    /**
     * MIT krb5 FIXUP(k) in s2k_des.c
     */
    public static void fixKey(byte[] key, int offset, int len) {
        if (isWeakKey(key, offset, len)) {
            key[offset + 7] ^= (byte) 0xf0;
        }
    }
}
