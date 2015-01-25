/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.kerby.util;

/**
 * Utility class for dealing with hex-encoding of binary data.
 *
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@gmail.com</a>
 * @since 13-Nov-2007
 */
public class Hex {

    public static byte[] decode(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            String hex = s.substring(2 * i, 2 * (i + 1));
            b[i] = (byte) Integer.parseInt(hex, 16);
        }
        return b;
    }

    public static byte[] decode(byte[] hexString) {
        byte[] b = new byte[hexString.length / 2];
        char[] chars = new char[2];
        for (int i = 0; i < b.length; i++) {
            chars[0] = (char) hexString[2 * i];
            chars[1] = (char) hexString[2 * i + 1];
            String hex = new String(chars);
            b[i] = (byte) Integer.parseInt(hex, 16);
        }
        return b;
    }

    public static String encode(byte[] b) {
        return encode(b, 0, b.length);
    }

    public static String encode(byte[] b, int offset, int length) {
        StringBuffer buf = new StringBuffer();
        int len = Math.min(offset + length, b.length);
        for (int i = offset; i < len; i++) {
            int c = (int) b[i];
            if (c < 0) {
                c = c + 256;
            }
            if (c >= 0 && c <= 15) {
                buf.append('0');
            }
            buf.append(Integer.toHexString(c));
        }
        return buf.toString();
    }

}
