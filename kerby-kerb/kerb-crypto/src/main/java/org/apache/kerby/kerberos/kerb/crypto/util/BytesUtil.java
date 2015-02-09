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

public class BytesUtil {

    public static short bytes2short(byte[] bytes, int offset, boolean bigEndian) {
        short val = 0;

        if (bigEndian) {
            val += (bytes[offset + 0] & 0xff) << 8;
            val += (bytes[offset + 1] & 0xff);
        } else {
            val += (bytes[offset + 1] & 0xff) << 8;
            val += (bytes[offset + 0] & 0xff);
        }

        return val;
    }

    public static short bytes2short(byte[] bytes, boolean bigEndian) {
        return bytes2short(bytes, 0, bigEndian);
    }

    public static byte[] short2bytes(int val, boolean bigEndian) {
        byte[] bytes = new byte[2];

        short2bytes(val, bytes, 0, bigEndian);

        return bytes;
    }

    public static void short2bytes(int val, byte[] bytes, int offset, boolean bigEndian) {
        if (bigEndian) {
            bytes[offset + 0] = (byte) ((val >> 8) & 0xff);
            bytes[offset + 1] = (byte) ((val) & 0xff);
        } else {
            bytes[offset + 1] = (byte) ((val >>  8) & 0xff);
            bytes[offset + 0] = (byte) ((val      ) & 0xff);
        }
    }

    public static int bytes2int(byte[] bytes, boolean bigEndian) {
        return bytes2int(bytes, 0, bigEndian);
    }

    public static int bytes2int(byte[] bytes, int offset, boolean bigEndian) {
        int val = 0;

        if (bigEndian) {
            val += (bytes[offset + 0] & 0xff) << 24;
            val += (bytes[offset + 1] & 0xff) << 16;
            val += (bytes[offset + 2] & 0xff) << 8;
            val += (bytes[offset + 3] & 0xff);
        } else {
            val += (bytes[offset + 3] & 0xff) << 24;
            val += (bytes[offset + 2] & 0xff) << 16;
            val += (bytes[offset + 1] & 0xff) << 8;
            val += (bytes[offset + 0] & 0xff);
        }

        return val;
    }

    public static byte[] int2bytes(int val, boolean bigEndian) {
        byte[] bytes = new byte[4];

        int2bytes(val, bytes, 0, bigEndian);

        return bytes;
    }

    public static void int2bytes(int val, byte[] bytes, int offset, boolean bigEndian) {
        if (bigEndian) {
            bytes[offset + 0] = (byte) ((val >> 24) & 0xff);
            bytes[offset + 1] = (byte) ((val >> 16) & 0xff);
            bytes[offset + 2] = (byte) ((val >> 8) & 0xff);
            bytes[offset + 3] = (byte) ((val) & 0xff);
        } else {
            bytes[offset + 3] = (byte) ((val >> 24) & 0xff);
            bytes[offset + 2] = (byte) ((val >> 16) & 0xff);
            bytes[offset + 1] = (byte) ((val >> 8) & 0xff);
            bytes[offset + 0] = (byte) ((val) & 0xff);
        }
    }

    public static byte[] long2bytes(long val, boolean bigEndian) {
        byte[] bytes = new byte[8];
        long2bytes(val, bytes, 0, bigEndian);
        return bytes;
    }

    public static void long2bytes(long val, byte[] bytes, int offset, boolean bigEndian) {
        if (bigEndian) {
            for (int i = 0; i < 8; i++) {
                bytes[i + offset] = (byte) ((val >> ((7 - i) * 8)) & 0xffL);
            }
        } else {
            for (int i = 0; i < 8; i++) {
                bytes[i + offset] = (byte) ((val >> (i * 8)) & 0xffL);
            }
        }
    }

    public static long bytes2long(byte[] bytes, boolean bigEndian) {
        return bytes2long(bytes, 0, bigEndian);
    }

    public static long bytes2long(byte[] bytes, int offset, boolean bigEndian) {
        long val = 0;

        if (bigEndian) {
            for (int i = 0; i < 8; i++) {
                val |= (((long) bytes[i + offset]) & 0xffL) << ((7 - i) * 8);
            }
        } else {
            for (int i = 0; i < 8; i++) {
                val |= (((long) bytes[i + offset]) & 0xffL) << (i * 8);
            }
        }

        return val;
    }

    public static byte[] padding(byte[] data, int block) {
        int len = data.length;
        int paddingLen = len % block != 0 ? 8 - len % block : 0;
        if (paddingLen == 0) {
            return data;
        }

        byte[] result = new byte[len + + paddingLen];
        System.arraycopy(data, 0, result, 0, len);
        return result;
    }

    public static byte[] duplicate(byte[] bytes) {
        return duplicate(bytes, 0, bytes.length);
    }

    public static byte[] duplicate(byte[] bytes, int offset, int len) {
        byte[] dup = new byte[len];
        System.arraycopy(bytes, offset, dup, 0, len);
        return dup;
    }

    public static void xor(byte[] input, int offset, byte[] output) {
        for (int i = 0; i < output.length / 4; ++i) {
            int a = BytesUtil.bytes2int(input, offset + i * 4, true);
            int b = BytesUtil.bytes2int(output, i * 4, true);
            b = a ^ b;
            BytesUtil.int2bytes(b, output, i * 4, true);
        }
    }

    public static void xor(byte[] a, byte[] b, byte[] output) {
        for (int i = 0; i < a.length / 4; ++i) {
            int av = BytesUtil.bytes2int(a, i * 4, true);
            int bv = BytesUtil.bytes2int(b, i * 4, true);
            int v = av ^ bv;
            BytesUtil.int2bytes(v, output, i * 4, true);
        }
    }
}
