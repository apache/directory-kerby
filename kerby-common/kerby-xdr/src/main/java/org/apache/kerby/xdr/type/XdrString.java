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
package org.apache.kerby.xdr.type;

import org.apache.kerby.xdr.XdrDataType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/*
 *  From RFC 4506 :
 *
 *  0     1     2     3     4     5   ...
 *        +-----+-----+-----+-----+-----+-----+...+-----+-----+...+-----+
 *        |        length n       |byte0|byte1|...| n-1 |  0  |...|  0  |
 *        +-----+-----+-----+-----+-----+-----+...+-----+-----+...+-----+
 *        |<-------4 bytes------->|<------n bytes------>|<---r bytes--->|
 *                                |<----n+r (where (n+r) mod 4 = 0)---->|
 *                                                                 STRING
 */
public class XdrString extends XdrSimple<String> {
    private int padding;

    public XdrString() {
        this((String) null);
    }

    public XdrString(String value) {
        super(XdrDataType.STRING, value);
    }

    @Override
    protected void toBytes() {
        if (getValue() != null) {
            /**Default value of byte is 0. So we don't have to initialize it with 0*/
            byte[] bytes = new byte[encodingBodyLength()];
            int length = bytes.length - padding - 4;
            bytes[0] = (byte) (length >> 24);
            bytes[1] = (byte) (length >> 16);
            bytes[2] = (byte) (length >> 8);
            bytes[3] = (byte) (length);
            System.arraycopy(getValue().getBytes(), 0, bytes, 4, length);
            setBytes(bytes);
        }
    }

    @Override
    protected int encodingBodyLength() {
        if (getValue() != null) {
            padding = (4 - getValue().length() % 4) % 4;
            return getValue().length() + padding + 4;
        }
        return 0;
    }

    protected void toValue() throws IOException {
        byte[] bytes = getBytes();
        byte[] header = new byte[4];
        System.arraycopy(bytes, 0, header, 0, 4);
        int stringLen  = ByteBuffer.wrap(header).getInt();
        int paddingBytes = (4 - (stringLen % 4)) % 4;
        validatePaddingBytes(paddingBytes);
        setPadding(paddingBytes);

        if (bytes.length != stringLen + 4 + paddingBytes) {
            int totalLength = stringLen + paddingBytes + 4;
            byte[] stringBytes = ByteBuffer.allocate(totalLength).put(getBytes(), 0, totalLength).array();
            setBytes(stringBytes); /**reset bytes in case the enum type is in a struct or union*/
        }

        byte[] content = new byte[stringLen];
        if (bytes.length > 1) {
            System.arraycopy(bytes, 4, content, 0, stringLen);
        }
        setValue(new String(content, StandardCharsets.US_ASCII));
    }

    public void setPadding(int padding) {
        this.padding = padding;
    }

    public int getPadding() {
        return padding;
    }

    public static String fromUTF8ByteArray(byte[] bytes) {
        int i = 0;
        int length = 0;

        while (i < bytes.length) {
            length++;
            if ((bytes[i] & 0xf0) == 0xf0) {
                // surrogate pair
                length++;
                i += 4;
            } else if ((bytes[i] & 0xe0) == 0xe0) {
                i += 3;
            } else if ((bytes[i] & 0xc0) == 0xc0) {
                i += 2;
            } else {
                i += 1;
            }
        }

        char[] cs = new char[length];
        i = 0;
        length = 0;

        while (i < bytes.length) {
            char ch;

            if ((bytes[i] & 0xf0) == 0xf0) {
                int codePoint = ((bytes[i] & 0x03) << 18) | ((bytes[i + 1] & 0x3F) << 12)
                        | ((bytes[i + 2] & 0x3F) << 6) | (bytes[i + 3] & 0x3F);
                int u = codePoint - 0x10000;
                char w1 = (char) (0xD800 | (u >> 10));
                char w2 = (char) (0xDC00 | (u & 0x3FF));
                cs[length++] = w1;
                ch = w2;
                i += 4;
            } else if ((bytes[i] & 0xe0) == 0xe0) {
                ch = (char) (((bytes[i] & 0x0f) << 12)
                        | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f));
                i += 3;
            } else if ((bytes[i] & 0xd0) == 0xd0) {
                ch = (char) (((bytes[i] & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
                i += 2;
            } else if ((bytes[i] & 0xc0) == 0xc0) {
                ch = (char) (((bytes[i] & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
                i += 2;
            } else {
                ch = (char) (bytes[i] & 0xff);
                i += 1;
            }

            cs[length++] = ch;
        }

        return new String(cs);
    }

    public static byte[] toUTF8ByteArray(String string) {
        return toUTF8ByteArray(string.toCharArray());
    }

    public static byte[] toUTF8ByteArray(char[] string) {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try {
            toUTF8ByteArray(string, bOut);
        } catch (IOException e) {
            throw new IllegalStateException("cannot encode string to byte array!");
        }

        return bOut.toByteArray();
    }

    public static void toUTF8ByteArray(char[] string, OutputStream sOut) throws IOException {
        char[] c = string;
        int i = 0;

        while (i < c.length) {
            char ch = c[i];

            if (ch < 0x0080) {
                sOut.write(ch);
            } else if (ch < 0x0800) {
                sOut.write(0xc0 | (ch >> 6));
                sOut.write(0x80 | (ch & 0x3f));
            } else if (ch >= 0xD800 && ch <= 0xDFFF) {
                // in error - can only happen, if the Java String class has a
                // bug.
                if (i + 1 >= c.length) {
                    throw new IllegalStateException("invalid UTF-16 codepoint");
                }
                char w1 = ch;
                ch = c[++i];
                char w2 = ch;
                // in error - can only happen, if the Java String class has a
                // bug.
                if (w1 > 0xDBFF) {
                    throw new IllegalStateException("invalid UTF-16 codepoint");
                }
                int codePoint = ((w1 & 0x03FF) << 10) | (w2 & 0x03FF) + 0x10000;
                sOut.write(0xf0 | (codePoint >> 18));
                sOut.write(0x80 | ((codePoint >> 12) & 0x3F));
                sOut.write(0x80 | ((codePoint >> 6) & 0x3F));
                sOut.write(0x80 | (codePoint & 0x3F));
            } else {
                sOut.write(0xe0 | (ch >> 12));
                sOut.write(0x80 | ((ch >> 6) & 0x3F));
                sOut.write(0x80 | (ch & 0x3F));
            }

            i++;
        }
    }

    /**
     * A locale independent version of toUpperCase.
     *
     * @param string input to be converted
     * @return a US Ascii uppercase version
     */
    public static String toUpperCase(String string) {
        boolean changed = false;
        char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++) {
            char ch = chars[i];
            if ('a' <= ch && 'z' >= ch) {
                changed = true;
                chars[i] = (char) (ch - 'a' + 'A');
            }
        }

        if (changed) {
            return new String(chars);
        }

        return string;
    }

    /**
     * A locale independent version of toLowerCase.
     *
     * @param string input to be converted
     * @return a US ASCII lowercase version
     */
    public static String toLowerCase(String string) {
        boolean changed = false;
        char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++) {
            char ch = chars[i];
            if ('A' <= ch && 'Z' >= ch) {
                changed = true;
                chars[i] = (char) (ch - 'A' + 'a');
            }
        }

        if (changed) {
            return new String(chars);
        }

        return string;
    }

    public static byte[] toByteArray(char[] chars) {
        byte[] bytes = new byte[chars.length];

        for (int i = 0; i != bytes.length; i++) {
            bytes[i] = (byte) chars[i];
        }

        return bytes;
    }

    public static byte[] toByteArray(String string) {
        byte[] bytes = new byte[string.length()];

        for (int i = 0; i != bytes.length; i++) {
            char ch = string.charAt(i);

            bytes[i] = (byte) ch;
        }

        return bytes;
    }

    /**
     * Convert an array of 8 bit characters into a string.
     *
     * @param bytes 8 bit characters.
     * @return resulting String.
     */
    public static String fromByteArray(byte[] bytes) {
        return new String(asCharArray(bytes));
    }

    /**
     * Do a simple conversion of an array of 8 bit characters into a string.
     *
     * @param bytes 8 bit characters.
     * @return resulting String.
     */
    public static char[] asCharArray(byte[] bytes) {
        char[] chars = new char[bytes.length];

        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return chars;
    }

    public static String[] split(String input, char delimiter) {
        List<String> v = new ArrayList<String>();
        boolean moreTokens = true;
        String subString;

        while (moreTokens) {
            int tokenLocation = input.indexOf(delimiter);
            if (tokenLocation > 0) {
                subString = input.substring(0, tokenLocation);
                v.add(subString);
                input = input.substring(tokenLocation + 1);
            } else {
                moreTokens = false;
                v.add(input);
            }
        }

        return v.toArray(new String[v.size()]);
    }

    private void validatePaddingBytes(int paddingBytes) throws IOException {
        if (paddingBytes < 0 || paddingBytes > 3) {
            throw new IOException("Bad padding number: " + paddingBytes + ", should be in [0, 3]");
        }
    }
}
