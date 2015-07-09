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

public class Util {

    static final String HEX_CHARS_STR = "0123456789ABCDEF";
    static final char[] HEX_CHARS = HEX_CHARS_STR.toCharArray();

    /**
     * Convert bytes into format as:
     * 0x02 02 00 80
     */
    public static String bytesToHex(byte[] bytes) {
        int len = bytes.length * 2;
        len += bytes.length; // for ' ' appended for each char
        len += 2; // for '0x' prefix
        char[] hexChars = new char[len];
        hexChars[0] = '0';
        hexChars[1] = 'x';
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 3 + 2] = HEX_CHARS[v >>> 4];
            hexChars[j * 3 + 3] = HEX_CHARS[v & 0x0F];
            hexChars[j * 3 + 4] = ' ';
        }

        return new String(hexChars);
    }

    /**
     * Convert hex string like follows into byte array
     * 0x02 02 00 80
     */
    public static byte[] hex2bytes(String hexString) {
        if (hexString == null) {
            throw new IllegalArgumentException("Invalid hex string to convert : null");
        }
        
        char[] hexStr = hexString.toCharArray();

        if (hexStr.length < 4) {
            throw new IllegalArgumentException("Invalid hex string to convert : length below 4");
        }
        
        if ((hexStr[0] != '0') || ((hexStr[1] != 'x') && (hexStr[1] != 'X'))) {
            throw new IllegalArgumentException("Invalid hex string to convert : not starting with '0x'");
        }
        
        byte[] bytes = new byte[(hexStr.length - 1) / 3];
        int pos = 0; 
        boolean high = false;
        boolean prefix = true;
        
        for (char c : hexStr) {
            if (prefix) {
                if ((c == 'x') || (c == 'X')) {
                    prefix = false;
                }
                
                continue;
            }
            
            switch (c) {
                case ' ' :
                    if (high) {
                        // We have had only the high part
                        throw new IllegalArgumentException("Invalid hex string to convert");
                    }
                    
                    // A hex pair has been decoded
                    pos++;
                    high = false;
                    break;
                    
                case '0': 
                case '1': 
                case '2': 
                case '3': 
                case '4':
                case '5': 
                case '6':
                case '7':
                case '8':
                case '9':
                    if (high) {
                        bytes[pos] += (byte) (c - '0');
                    } else {
                        bytes[pos] = (byte) ((c - '0') << 4);
                    }
                    
                    high = !high;
                    break;
                    
                case 'a' :
                case 'b' :
                case 'c' :
                case 'd' :
                case 'e' :
                case 'f' :
                    if (high) {
                        bytes[pos] += (byte) (c - 'a' + 10);
                    } else {
                        bytes[pos] = (byte) ((c - 'a' + 10) << 4);
                    }

                    high = !high;
                    break;

                case 'A' :
                case 'B' :
                case 'C' :
                case 'D' :
                case 'E' :
                case 'F' :
                    if (high) {
                        bytes[pos] += (byte) (c - 'A' + 10);
                    } else {
                        bytes[pos] = (byte) ((c - 'A' + 10) << 4);
                    }

                    high = !high;
                    break;
                    
                default :
                    throw new IllegalArgumentException("Invalid hex string to convert");
            }
        }
        
        if (high) {
            throw new IllegalArgumentException("Invalid hex string to convert");
        }

        return bytes;
    }
}
