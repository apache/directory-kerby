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
package org.apache.kerby.util;

public class HexUtil {

    final static String HEX_CHARS_STR = "0123456789ABCDEF";
    final static char[] HEX_CHARS = HEX_CHARS_STR.toCharArray();

    /**
     * Convert bytes into format as:
     * 02020080
     */
    public static String bytesToHex(byte[] bytes) {
        int len = bytes.length * 2;
        char[] hexChars = new char[len];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_CHARS[v >>> 4];
            hexChars[j * 2 + 1] = HEX_CHARS[v & 0x0F];
        }

        return new String(hexChars);
    }

    /**
     * Convert hex string like follows into byte array
     * 02020080
     */
    public static byte[] hex2bytes(String hexString) {
        hexString = hexString.toUpperCase();
        int len = hexString.length() / 2;
        byte[] bytes = new byte[len];
        char[] hexChars = hexString.toCharArray();
        for (int i = 0, j = 0; i < len; ++i) {
            bytes[i] = (byte) ((HEX_CHARS_STR.indexOf(hexChars[j++]) << 4) + HEX_CHARS_STR.indexOf(hexChars[j++]));
        }

        return bytes;
    }
}
