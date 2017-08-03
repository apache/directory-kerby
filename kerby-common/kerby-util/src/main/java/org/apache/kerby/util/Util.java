/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/Util.java $
 * $Revision: 180 $
 * $Date: 2014-09-23 11:33:47 -0700 (Tue, 23 Sep 2014) $
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

package org.apache.kerby.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 28-Feb-2006
 */
public class Util {
    public static final int SIZE_KEY = 0;
    public static final int LAST_READ_KEY = 1;

    /**
     * True if the Keystores have the same # of entries, have the same set of aliases, and all the certificate-chains
     * (of the certificate entries) match.   Does not check the private keys for equality, since we
     * don't bother taking the passwords to get at them.
     * @param ks1 The first key store
     * @param ks2 The second key store
     * @return boolean
     * @throws KeyStoreException e
     */
    public static boolean equals(KeyStore ks1, KeyStore ks2) throws KeyStoreException {
        if (ks1 == null || ks2 == null) {
            return ks1 == null && ks2 == null;
        }
        Set<String> aliases1 = aliases(ks1);
        Set<String> aliases2 = aliases(ks2);
        if (aliases1.equals(aliases2)) {
            for (String s : aliases1) {
                if (ks1.isCertificateEntry(s) != ks2.isCertificateEntry(s)) {
                    return false;
                }
                if (ks1.isKeyEntry(s) != ks2.isKeyEntry(s)) {
                    return false;
                }
                if (ks1.isCertificateEntry(s)) {
                    Certificate[] cc1 = ks1.getCertificateChain(s);
                    Certificate[] cc2 = ks2.getCertificateChain(s);
                    if (!Arrays.equals(cc1, cc2)) {
                        return false;
                    }

                    Certificate c1 = ks1.getCertificate(s);
                    Certificate c2 = ks2.getCertificate(s);
                    if (!c1.equals(c2)) {
                        return false;
                    }
                }

                // should we bother checking keys?   maybe one day....
            }
        }
        return true;
    }

    private static Set<String> aliases(KeyStore ks) throws KeyStoreException {
        Set<String> aliases = new TreeSet<String>();
        Enumeration<String> en = ks.aliases();
        while (en.hasMoreElements()) {
            aliases.add(en.nextElement());
        }
        return aliases;
    }

    public static boolean isYes(String yesString) {
        if (yesString == null) {
            return false;
        }
        String s = yesString.trim().toUpperCase();
        return "1".equals(s) || "YES".equals(s) || "TRUE".equals(s)
               || "ENABLE".equals(s) || "ENABLED".equals(s) || "Y".equals(s)
               || "ON".equals(s);
    }

    public static String trim(final String s) {
        if (s == null || "".equals(s)) {
            return s;
        }
        int i = 0;
        int j = s.length() - 1;
        while (isWhiteSpace(s.charAt(i))) {
            i++;
        }
        while (isWhiteSpace(s.charAt(j))) {
            j--;
        }
        return j >= i ? s.substring(i, j + 1) : "";
    }

    public static boolean isWhiteSpace(final char c) {
        switch (c) {
            case 0:
            case ' ':
            case '\t':
            case '\n':
            case '\r':
            case '\f':
                return true;
            default:
                return false;
        }
    }

    public static void pipeStream(InputStream in, OutputStream out)
        throws IOException {
        pipeStream(in, out, true);
    }

    public static void pipeStream(InputStream in, OutputStream out,
                                  boolean autoClose)
        throws IOException {
        byte[] buf = new byte[8192];
        IOException ioe = null;
        try {
            int bytesRead = in.read(buf);
            while (bytesRead >= 0) {
                if (bytesRead > 0) {
                    out.write(buf, 0, bytesRead);
                }
                bytesRead = in.read(buf);
            }
        } finally {
            // Probably it's best to let consumer call "close", but I'm usually
            // the consumer, and I want to be lazy.  [Julius, November 20th, 2006]
            try {
                in.close();
            } catch (IOException e) {
                ioe = e;
            }
            if (autoClose) {
                try {
                    out.close();
                } catch (IOException e) {
                    ioe = e;
                }
            }
        }
        if (ioe != null) {
            throw ioe;
        }
    }

    public static byte[] fileToBytes(final File f) throws IOException {
        return streamToBytes(Files.newInputStream(f.toPath()));
    }

    public static byte[] streamToBytes(final ByteArrayInputStream in,
                                       int maxLength) {
        byte[] buf = new byte[maxLength];
        int[] status = fill(buf, 0, in);
        int size = status[SIZE_KEY];
        if (buf.length != size) {
            byte[] smallerBuf = new byte[size];
            System.arraycopy(buf, 0, smallerBuf, 0, size);
            buf = smallerBuf;
        }
        return buf;
    }

    public static byte[] streamToBytes(final InputStream in, int maxLength)
        throws IOException {
        byte[] buf = new byte[maxLength];
        int[] status = fill(buf, 0, in);
        int size = status[SIZE_KEY];
        if (buf.length != size) {
            byte[] smallerBuf = new byte[size];
            System.arraycopy(buf, 0, smallerBuf, 0, size);
            buf = smallerBuf;
        }
        return buf;
    }

    public static byte[] streamToBytes(final InputStream in) throws IOException {
        byte[] buf = new byte[4096];
        try {
            int[] status = fill(buf, 0, in);
            int size = status[SIZE_KEY];
            int lastRead = status[LAST_READ_KEY];
            while (lastRead != -1) {
                buf = resizeArray(buf);
                status = fill(buf, size, in);
                size = status[SIZE_KEY];
                lastRead = status[LAST_READ_KEY];
            }
            if (buf.length != size) {
                byte[] smallerBuf = new byte[size];
                System.arraycopy(buf, 0, smallerBuf, 0, size);
                buf = smallerBuf;
            }
        } finally {
            in.close();
        }
        return buf;
    }

    public static byte[] streamToBytes(final ByteArrayInputStream in) {
        byte[] buf = new byte[4096];
        int[] status = fill(buf, 0, in);
        int size = status[SIZE_KEY];
        int lastRead = status[LAST_READ_KEY];
        while (lastRead != -1) {
            buf = resizeArray(buf);
            status = fill(buf, size, in);
            size = status[SIZE_KEY];
            lastRead = status[LAST_READ_KEY];
        }
        if (buf.length != size) {
            byte[] smallerBuf = new byte[size];
            System.arraycopy(buf, 0, smallerBuf, 0, size);
            buf = smallerBuf;
        }
        // in.close();  <-- this is a no-op on ByteArrayInputStream.
        return buf;
    }

    public static int[] fill(final byte[] buf, final int offset,
                             final InputStream in)
        throws IOException {
        int read = in.read(buf, offset, buf.length - offset);
        int lastRead = read;
        if (read == -1) {
            read = 0;
        }
        while (lastRead != -1 && read + offset < buf.length) {
            lastRead = in.read(buf, offset + read, buf.length - read - offset);
            if (lastRead != -1) {
                read += lastRead;
            }
        }
        return new int[]{offset + read, lastRead};
    }

    public static int[] fill(final byte[] buf, final int offset,
                             final ByteArrayInputStream in) {
        int read = in.read(buf, offset, buf.length - offset);
        int lastRead = read;
        if (read == -1) {
            read = 0;
        }
        while (lastRead != -1 && read + offset < buf.length) {
            lastRead = in.read(buf, offset + read, buf.length - read - offset);
            if (lastRead != -1) {
                read += lastRead;
            }
        }
        return new int[]{offset + read, lastRead};
    }

    public static byte[] resizeArray(final byte[] bytes) {
        byte[] biggerBytes = new byte[bytes.length * 2];
        System.arraycopy(bytes, 0, biggerBytes, 0, bytes.length);
        return biggerBytes;
    }

    public static String pad(String s, final int length, final boolean left) {
        if (s == null) {
            s = "";
        }
        int diff = length - s.length();
        if (diff == 0) {
            return s;
        } else if (diff > 0) {
            StringBuilder sb = new StringBuilder();
            if (left) {
                for (int i = 0; i < diff; i++) {
                    sb.append(' ');
                }
            }
            sb.append(s);
            if (!left) {
                for (int i = 0; i < diff; i++) {
                    sb.append(' ');
                }
            }
            return sb.toString();
        } else {
            return s;
        }
    }

    public static HostPort toAddress(final String target,
                                     final int defaultPort)
        throws UnknownHostException {
        String host = target;
        int port = defaultPort;
        StringTokenizer st = new StringTokenizer(target, ":");
        if (st.hasMoreTokens()) {
            host = st.nextToken().trim();
        }
        if (st.hasMoreTokens()) {
            port = Integer.parseInt(st.nextToken().trim());
        }
        if (st.hasMoreTokens()) {
            throw new IllegalArgumentException("Invalid host: " + target);
        }
        return new HostPort(host, port);
    }

    public static String cipherToAuthType(String cipher) {
        if (cipher == null) {
            return null;
        }

        // SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA  ==> "DHE_DSS_EXPORT"
        // SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA      ==> "DHE_DSS"
        // SSL_RSA_WITH_3DES_EDE_CBC_SHA          ==> "RSA"

        StringTokenizer st = new StringTokenizer(cipher.trim(), "_");
        if (st.hasMoreTokens()) {
            st.nextToken();  // always skip first token
        }
        if (st.hasMoreTokens()) {
            String tok = st.nextToken();
            StringBuilder buf = new StringBuilder();
            buf.append(tok);
            if (st.hasMoreTokens()) {
                tok = st.nextToken();
                while (!"WITH".equalsIgnoreCase(tok)) {
                    buf.append('_');
                    buf.append(tok);
                    tok = st.nextToken();
                }
            }
            return buf.toString();
        }
        throw new IllegalArgumentException("not a valid cipher: " + cipher);
    }

    /**
     * Utility method to make sure IP-literals don't trigger reverse-DNS lookups.
     * @param s The string
     * @return The InetAddress
     * @throws UnknownHostException e
     */
    public static InetAddress toInetAddress(String s) throws UnknownHostException {
        byte[] ip = IPAddressParser.parseIPv4Literal(s);
        if (ip == null) {
            ip = IPAddressParser.parseIPv6Literal(s);
        }
        if (ip != null) {
            // Strangely, this prevents Java's annoying SSL reverse-DNS lookup that it
            // normally does, even with literal IP addresses.
            return InetAddress.getByAddress(s, ip);
        } else {
            return InetAddress.getByName(s);
        }
    }

    public static void main(String[] args) throws Exception {
        String s = "line1\n\rline2\n\rline3";
        ByteArrayInputStream in = new ByteArrayInputStream(s.getBytes(Charset.forName("UTF-8")));
        ByteArrayReadLine readLine = new ByteArrayReadLine(in);
        String line = readLine.next();
        while (line != null) {
            System.out.println(line);
            line = readLine.next();
        }

        System.out.println("--------- test 2 ----------");

        s = "line1\n\rline2\n\rline3\n\r\n\r";
        in = new ByteArrayInputStream(s.getBytes());
        readLine = new ByteArrayReadLine(in);
        line = readLine.next();
        while (line != null) {
            System.out.println(line);
            line = readLine.next();
        }

    }


}
