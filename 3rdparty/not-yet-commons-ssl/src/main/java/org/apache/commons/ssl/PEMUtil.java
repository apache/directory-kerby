/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/PEMUtil.java $
 * $Revision: 153 $
 * $Date: 2009-09-15 22:40:53 -0700 (Tue, 15 Sep 2009) $
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

package org.apache.commons.ssl;

import org.apache.commons.ssl.util.ByteArrayReadLine;
import org.apache.kerby.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.PublicKey;
import java.util.*;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 13-Aug-2006
 */
public class PEMUtil {
    final static String LINE_SEPARATOR = System.getProperty("line.separator");

    public static byte[] encode(Collection items) throws IOException {
        final byte[] LINE_SEPARATOR_BYTES = LINE_SEPARATOR.getBytes("UTF-8");
        ByteArrayOutputStream out = new ByteArrayOutputStream(8192);
        Iterator it = items.iterator();
        while (it.hasNext()) {
            PEMItem item = (PEMItem) it.next();
            out.write("-----BEGIN ".getBytes("UTF-8"));
            out.write(item.pemType.getBytes("UTF-8"));
            out.write("-----".getBytes("UTF-8"));
            out.write(LINE_SEPARATOR_BYTES);

            byte[] derBytes = item.getDerBytes();
            ByteArrayInputStream bin = new ByteArrayInputStream(derBytes);
            byte[] line = Util.streamToBytes(bin, 48);
            while (line.length == 48) {
                byte[] base64Line = Base64.encodeBase64(line);
                out.write(base64Line);
                out.write(LINE_SEPARATOR_BYTES);
                line = Util.streamToBytes(bin, 48);
            }
            if (line.length > 0) {
                byte[] base64Line = Base64.encodeBase64(line);
                out.write(base64Line);
                out.write(LINE_SEPARATOR_BYTES);
            }
            out.write("-----END ".getBytes("UTF-8"));
            out.write(item.pemType.getBytes("UTF-8"));
            out.write("-----".getBytes("UTF-8"));
            out.write(LINE_SEPARATOR_BYTES);
        }
        return out.toByteArray();
    }

    public static List decode(byte[] pemBytes) {
        LinkedList pemItems = new LinkedList();
        ByteArrayInputStream in = new ByteArrayInputStream(pemBytes);
        ByteArrayReadLine readLine = new ByteArrayReadLine(in);
        String line = readLine.next();
        while (line != null) {
            int len = 0;
            byte[] decoded;
            ArrayList listOfByteArrays = new ArrayList(64);
            Map properties = new HashMap();
            String type = "[unknown]";
            while (line != null && !beginBase64(line)) {
                line = readLine.next();
            }
            if (line != null) {
                String upperLine = line.toUpperCase();
                int x = upperLine.indexOf("-BEGIN") + "-BEGIN".length();
                int y = upperLine.indexOf("-", x);
                type = upperLine.substring(x, y).trim();
                line = readLine.next();
            }
            while (line != null && !endBase64(line)) {
                line = Util.trim(line);
                if (!"".equals(line)) {
                    int x = line.indexOf(':');
                    if (x > 0) {
                        String k = line.substring(0, x).trim();
                        String v = "";
                        if (line.length() > x + 1) {
                            v = line.substring(x + 1).trim();
                        }
                        properties.put(k.toLowerCase(), v.toLowerCase());
                    } else {
                        byte[] base64 = line.getBytes();
                        byte[] rawBinary = Base64.decodeBase64(base64);
                        listOfByteArrays.add(rawBinary);
                        len += rawBinary.length;
                    }
                }
                line = readLine.next();
            }
            if (line != null) {
                line = readLine.next();
            }

            if (!listOfByteArrays.isEmpty()) {
                decoded = new byte[len];
                int pos = 0;
                Iterator it = listOfByteArrays.iterator();
                while (it.hasNext()) {
                    byte[] oneLine = (byte[]) it.next();
                    System.arraycopy(oneLine, 0, decoded, pos, oneLine.length);
                    pos += oneLine.length;
                }
                PEMItem item = new PEMItem(decoded, type, properties);
                pemItems.add(item);
            }
        }

        // closing ByteArrayInputStream is a NO-OP
        // in.close();

        return pemItems;
    }

    private static boolean beginBase64(String line) {
        line = line != null ? line.trim().toUpperCase() : "";
        int x = line.indexOf("-BEGIN");
        return x > 0 && startsAndEndsWithDashes(line);
    }

    private static boolean endBase64(String line) {
        line = line != null ? line.trim().toUpperCase() : "";
        int x = line.indexOf("-END");
        return x > 0 && startsAndEndsWithDashes(line);
    }

    private static boolean startsAndEndsWithDashes(String line) {
        line = Util.trim(line);
        char c = line.charAt(0);
        char d = line.charAt(line.length() - 1);
        return c == '-' && d == '-';
    }

    public static String formatRSAPrivateKey(RSAPrivateCrtKey key) {
        StringBuffer buf = new StringBuffer(2048);
        buf.append("Private-Key:");
        buf.append(LINE_SEPARATOR);
        buf.append("modulus:");
        buf.append(LINE_SEPARATOR);
        buf.append(formatBigInteger(key.getModulus(), 129 * 2));
        buf.append(LINE_SEPARATOR);
        buf.append("publicExponent: ");
        buf.append(key.getPublicExponent());
        buf.append(LINE_SEPARATOR);
        buf.append("privateExponent:");
        buf.append(LINE_SEPARATOR);
        buf.append(formatBigInteger(key.getPrivateExponent(), 128 * 2));
        buf.append(LINE_SEPARATOR);
        buf.append("prime1:");
        buf.append(LINE_SEPARATOR);
        buf.append(formatBigInteger(key.getPrimeP(), 65 * 2));
        buf.append(LINE_SEPARATOR);
        buf.append("prime2:");
        buf.append(LINE_SEPARATOR);
        buf.append(formatBigInteger(key.getPrimeQ(), 65 * 2));
        buf.append(LINE_SEPARATOR);
        buf.append("exponent1:");
        buf.append(LINE_SEPARATOR);
        buf.append(formatBigInteger(key.getPrimeExponentP(), 65 * 2));
        buf.append(LINE_SEPARATOR);
        buf.append("exponent2:");
        buf.append(LINE_SEPARATOR);
        buf.append(formatBigInteger(key.getPrimeExponentQ(), 65 * 2));
        buf.append(LINE_SEPARATOR);
        buf.append("coefficient:");
        buf.append(LINE_SEPARATOR);
        buf.append(formatBigInteger(key.getCrtCoefficient(), 65 * 2));
        return buf.toString();
    }

    public static String formatBigInteger(BigInteger bi, int length) {
        String s = bi.toString(16);
        StringBuffer buf = new StringBuffer(s.length());
        int zeroesToAppend = length - s.length();
        int count = 0;
        buf.append("    ");
        for (int i = 0; i < zeroesToAppend; i++) {
            count++;
            buf.append('0');
            if (i % 2 == 1) {
                buf.append(':');
            }
        }
        for (int i = 0; i < s.length() - 2; i++) {
            count++;
            buf.append(s.charAt(i));
            if (i % 2 == 1) {
                buf.append(':');
            }
            if (count % 30 == 0) {
                buf.append(LINE_SEPARATOR);
                buf.append("    ");
            }
        }
        buf.append(s.substring(s.length() - 2));
        return buf.toString();
    }

    public static String toPem(PublicKey key) throws IOException {
        PEMItem item = null;
        if (key instanceof RSAPublicKey) {
            item = new PEMItem(key.getEncoded(), "PUBLIC KEY");
        } else if (key instanceof DSAPublicKey) {
            item = new PEMItem(key.getEncoded(), "PUBLIC KEY");
        } else {
            throw new IOException("Not an RSA or DSA key");
        }
        byte[] pem = encode(Collections.singleton(item));
        return new String(pem, "UTF-8");
    }

}
