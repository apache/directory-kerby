/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/trunk/src/java/org/apache/commons/ssl/util/IPAddressParser.java $
 * $Revision: 121 $
 * $Date: 2007-11-13 21:26:57 -0800 (Tue, 13 Nov 2007) $
 *
 * ====================================================================
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
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */
package org.apache.commons.ssl.util;

/**
 * Parses String representations of IPv4 and IPv6 addresses, and converts
 * them to byte[].  Returns null if the supplied String is not a valid IP
 * address.
 * <p/>
 * IPv6 addresses are allowed to include square brackets (e.g., "[::a:b:c:d]"),
 * but IPv4 addresses are not.  This is to help in situation where an IPv6
 * literal address is encoded directly inside a URL (the square brackets allow
 * the web client to separate the IPv6 address from its port, since the colon
 * character is overloaded in that context).
 */
public class IPAddressParser {

    /**
     * Converts the supplied IPv4 literal to byte[], or null if the
     * IPv4 address was invalid.
     *
     * @param s Literal IPv4 address.
     * @return byte[] array or null if the supplied IPv4 address was invalid.
     */
    public static byte[] parseIPv4Literal(String s) {
        s = s != null ? s.trim() : "";
        String[] toks = s.split("\\.");
        byte[] ip = new byte[4];
        if (toks.length == 4) {
            for (int i = 0; i < ip.length; i++) {
                try {
                    int val = Integer.parseInt(toks[i]);
                    if (val < 0 || val > 255) {
                        return null;
                    }
                    ip[i] = (byte) val;
                } catch (NumberFormatException nfe) {
                    return null;
                }
            }
            return ip;
        }
        return null;
    }

    /**
     * Converts the supplied IPv6 literal to byte[], or null if the
     * IPv6 address was invalid.
     *
     * @param s Literal IPv6 address.
     * @return byte[] array or null if the supplied IPv6 address was invalid.
     */
    public static byte[] parseIPv6Literal(String s) {
        s = s != null ? s.trim() : "";
        if (s.length() > 0 && s.charAt(0) == '[' && s.charAt(s.length() - 1) == ']') {
            s = s.substring(1, s.length() - 1).trim();
        }
        int x = s.lastIndexOf(':');
        int y = s.indexOf('.');
        // Contains a dot!  Look for IPv4 literal suffix.
        if (x >= 0 && y > x) {
            byte[] ip4Suffix = parseIPv4Literal(s.substring(x + 1));
            if (ip4Suffix == null) {
                return null;
            }
            s = s.substring(0, x) + ":" + ip4ToHex(ip4Suffix);
        }

        // Check that we only have a single occurence of "::".
        x = s.indexOf("::");
        if (x >= 0) {
            if (s.indexOf("::", x + 1) >= 0) {
                return null;
            }
        }

        // This array helps us expand the "::" into the zeroes it represents.
        String[] raw = new String[]{"0000", "0000", "0000", "0000", "0000", "0000", "0000", "0000"};
        if (s.indexOf("::") >= 0) {
            String[] split = s.split("::", -1);
            String[] prefix = splitOnColon(split[0]);
            String[] suffix = splitOnColon(split[1]);

            // Make sure the "::" zero-expander has some room to expand!
            if (prefix.length + suffix.length > 7) {
                return null;
            }
            for (int i = 0; i < prefix.length; i++) {
                raw[i] = prependZeroes(prefix[i]);
            }
            int startPos = raw.length - suffix.length;
            for (int i = 0; i < suffix.length; i++) {
                raw[startPos + i] = prependZeroes(suffix[i]);
            }
        } else {
            // Okay, whew, no "::" zero-expander, but we still have to make sure
            // each element contains 4 hex characters.
            raw = splitOnColon(s);
            if (raw.length != 8) {
                return null;
            }
            for (int i = 0; i < raw.length; i++) {
                raw[i] = prependZeroes(raw[i]);
            }
        }

        byte[] ip6 = new byte[16];
        int i = 0;
        for (int j = 0; j < raw.length; j++) {
            String tok = raw[j];
            if (tok.length() > 4) {
                return null;
            }
            String prefix = tok.substring(0, 2);
            String suffix = tok.substring(2, 4);
            try {
                ip6[i++] = (byte) Integer.parseInt(prefix, 16);
                ip6[i++] = (byte) Integer.parseInt(suffix, 16);
            } catch (NumberFormatException nfe) {
                return null;
            }
        }
        return ip6;
    }

    private static String prependZeroes(String s) {
        switch (s.length()) {
            case 0: return "0000";
            case 1: return "000" + s;
            case 2: return "00" + s;
            case 3: return "0" + s;
            default: return s;
        }
    }

    private static String[] splitOnColon(String s) {
        if ("".equals(s)) {
            return new String[]{};
        } else {
            return s.split(":");
        }
    }

    private static String ip4ToHex(byte[] b) {
        return b2s(b[0]) + b2s(b[1]) + ":" + b2s(b[2]) + b2s(b[3]);
    }

    private static String b2s(byte b) {
        String s = Integer.toHexString(b >= 0 ? b : 256 + b);
        if (s.length() < 2) {
            s = "0" + s;
        }
        return s;
    }
}
