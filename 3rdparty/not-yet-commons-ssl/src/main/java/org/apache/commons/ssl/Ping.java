/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/Ping.java $
 * $Revision: 142 $
 * $Date: 2008-03-04 00:13:37 -0800 (Tue, 04 Mar 2008) $
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

import org.apache.commons.ssl.util.ReadLine;

import javax.net.ssl.SSLSocket;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 30-Mar-2006
 */
public class Ping {
    protected static SortedSet args = new TreeSet();
    protected static Map argsMatch = new HashMap();
    protected static final Arg ARG_TARGET = new Arg("-t", "--target",
        "[hostname[:port]]              default port=443", true);
    protected static final Arg ARG_BIND = new Arg("-b", "--bind",
        "[hostname[:port]]              default port=0 \"ANY\"");
    protected static final Arg ARG_PROXY = new Arg("-r", "--proxy",
        "[hostname[:port]]              default port=80");
    protected static final Arg ARG_TRUST_CERT = new Arg("-tm",
        "--trust-cert", "[path to trust material]       {pem, der, crt, jks}");
    protected static final Arg ARG_CLIENT_CERT = new Arg("-km",
        "--client-cert", "[path to client's private key] {jks, pkcs12, pkcs8}");
    protected static final Arg ARG_CERT_CHAIN = new Arg("-cc",
        "--cert-chain", "[path to client's cert chain for pkcs8/OpenSSL key]");
    protected static final Arg ARG_PASSWORD = new Arg("-p", "--password", "[client cert password]");
    protected static final Arg ARG_HOST_HEADER = new Arg("-h",
        "--host-header", "[http-host-header]      in case -t is an IP address");
    protected static final Arg ARG_PATH = new Arg("-u", "--path",
        "[path for GET/HEAD request]    default=/");
    protected static final Arg ARG_METHOD = new Arg("-m", "--method",
        "[http method to use]           default=HEAD");

    private static HostPort target;
    private static HostPort local;
    private static HostPort proxy;
    private static String hostHeader;
    private static String httpMethod = "HEAD";
    private static String path = "/";
    private static InetAddress targetAddress;
    private static InetAddress localAddress;
    private static int targetPort = 443;
    private static int localPort = 0;
    private static File clientCert;
    private static File certChain;
    private static char[] password;
    private static TrustChain trustChain = null;

    static {
        args = Collections.unmodifiableSortedSet(args);
        argsMatch = Collections.unmodifiableMap(argsMatch);
    }

    public static void printUsage(Exception parseException) {
        if (parseException != null) {
            System.out.println();
            System.out.println("* Error: " + parseException.getMessage() + ".");
            parseException.printStackTrace(System.out);
            System.out.println();
        }
        System.out.println("Usage:  java -jar not-yet-commons-ssl-" + Version.VERSION + ".jar [options]");
        System.out.println(Version.versionString());
        System.out.println("Options:   (*=required)");
        Iterator it = Ping.args.iterator();
        while (it.hasNext()) {
            Arg a = (Arg) it.next();
            String s = Util.pad(a.shortArg, 3, false);
            String l = Util.pad(a.longArg, 18, false);
            String required = a.isRequired ? "*" : " ";
            String d = a.description;
            System.out.println(required + "  " + s + " " + l + " " + d);
        }
        System.out.println();
        String example = "java -jar commons-ssl.jar -t host.com:443 -c ./client.pfx -p `cat ./pass.txt` ";
        System.out.println("Example:");
        System.out.println();
        System.out.println(example);
        System.out.println();
        System.exit(1);
        return;
    }

    public static void main(String[] args) throws Exception {
        boolean showUsage = args.length == 0;
        Exception parseException = null;
        if (!showUsage) {
            try {
                parseArgs(args);
            } catch (Exception e) {
                parseException = e;
                showUsage = true;
            }
        }
        if (showUsage) {
            printUsage(parseException);
        }

        SSLClient ssl = new SSLClient();
        Socket s = null;
        InputStream in = null;
        OutputStream out = null;
        Exception socketException = null;
        Exception trustException = null;
        Exception hostnameException = null;
        Exception crlException = null;
        Exception expiryException = null;
        String sslCipher = null;
        try {
            try {
                ssl.setCheckHostname(false);
                ssl.setCheckExpiry(false);
                ssl.setCheckCRL(false);
                ssl.addTrustMaterial(TrustMaterial.TRUST_ALL);
                if (clientCert != null) {

                    KeyMaterial km;
                    if (certChain != null) {
                        km = new KeyMaterial(clientCert, certChain, password);
                    } else {
                        km = new KeyMaterial(clientCert, password);
                    }
                    if (password != null) {
                        for (int i = 0; i < password.length; i++) {
                            password[i] = 0;
                        }
                    }
                    ssl.setKeyMaterial(km);
                }

                if (trustChain != null) {
                    ssl.addTrustMaterial(trustChain);
                }

                ssl.setSoTimeout(10000);
                ssl.setConnectTimeout(5000);

                if (proxy != null) {
                    s = new Socket(proxy.host, proxy.port,
                        local.addr, local.port);
                    s.setSoTimeout(10000);
                    in = s.getInputStream();
                    out = s.getOutputStream();
                    String targetHost = target.host;
                    String line1 = "CONNECT " + targetHost + ":" + targetPort + " HTTP/1.1\r\n";
                    String line2 = "Proxy-Connection: keep-alive\r\n";
                    String line3 = "Host: " + targetHost + "\r\n\r\n";
                    out.write(line1.getBytes());
                    out.write(line2.getBytes());
                    out.write(line3.getBytes());
                    out.flush();

                    ReadLine readLine = new ReadLine(in);
                    String read1 = readLine.next();
                    if (read1.startsWith("HTTP/1.1 200")) {
                        int avail = in.available();
                        in.skip(avail);
                        Thread.yield();
                        avail = in.available();
                        while (avail != 0) {
                            in.skip(avail);
                            Thread.yield();
                            avail = in.available();
                        }
                        s = ssl.createSocket(s, targetHost, targetPort, true);
                    } else {
                        System.out.print(line1);
                        System.out.print(line2);
                        System.out.print(line3);
                        System.out.println("Server returned unexpected proxy response!");
                        System.out.println("=============================================");
                        System.out.println(read1);
                        String line = readLine.next();
                        while (line != null) {
                            System.out.println(line);
                            line = readLine.next();
                        }
                        System.exit(1);
                    }
                } else {
                    s = ssl.createSocket(targetAddress, targetPort,
                        localAddress, localPort);
                }

                sslCipher = ((SSLSocket) s).getSession().getCipherSuite();
                System.out.println("Cipher: " + sslCipher);
                System.out.println("================================================================================");

                String line1 = httpMethod + " " + path + " HTTP/1.1";
                if (hostHeader == null) {
                    hostHeader = targetAddress.getHostName();
                }
                String line2 = "Host: " + hostHeader;
                byte[] crlf = {'\r', '\n'};

                System.out.println("Writing: ");
                System.out.println("================================================================================");
                System.out.println(line1);
                System.out.println(line2);
                System.out.println();

                out = s.getOutputStream();
                out.write(line1.getBytes());
                out.write(crlf);
                out.write(line2.getBytes());
                out.write(crlf);
                out.write(crlf);
                out.flush();

                in = s.getInputStream();

                int c = in.read();
                StringBuffer buf = new StringBuffer();
                System.out.println("Reading: ");
                System.out.println("================================================================================");
                while (c >= 0) {
                    byte b = (byte) c;
                    buf.append((char) b);
                    System.out.print((char) b);
                    if (-1 == buf.toString().indexOf("\r\n\r\n")) {
                        c = in.read();
                    } else {
                        break;
                    }
                }
            } catch (Exception e) {
                socketException = e;
            }
            trustException = testTrust(ssl, sslCipher, trustChain);
            hostnameException = testHostname(ssl);
            crlException = testCRL(ssl);
            expiryException = testExpiry(ssl);
        } finally {
            if (out != null) {
                out.close();
            }
            if (in != null) {
                in.close();
            }
            if (s != null) {
                s.close();
            }

            X509Certificate[] peerChain = ssl.getCurrentServerChain();
            if (peerChain != null) {
                String title = "Server Certificate Chain for: ";
                title = peerChain.length > 1 ? title : "Server Certificate for: ";
                System.out.println(title + "[" + target + "]");
                System.out.println("================================================================================");
                for (int i = 0; i < peerChain.length; i++) {
                    X509Certificate cert = peerChain[i];
                    String certAsString = Certificates.toString(cert);
                    String certAsPEM = Certificates.toPEMString(cert);
                    if (i > 0) {
                        System.out.println();
                    }
                    System.out.print(certAsString);
                    System.out.print(certAsPEM);
                }
            }
            if (hostnameException != null) {
                hostnameException.printStackTrace();
                System.out.println();
            }
            if (crlException != null) {
                crlException.printStackTrace();
                System.out.println();
            }
            if (expiryException != null) {
                expiryException.printStackTrace();
                System.out.println();
            }
            if (trustException != null) {
                trustException.printStackTrace();
                System.out.println();
            }
            if (socketException != null) {
                socketException.printStackTrace();
                System.out.println();
            }
        }
    }

    private static Exception testTrust(SSLClient ssl, String cipher,
                                       TrustChain tc) {
        try {
            X509Certificate[] chain = ssl.getCurrentServerChain();
            String authType = Util.cipherToAuthType(cipher);
            if (authType == null) {
                // default of "RSA" just for Ping's purposes.
                authType = "RSA";
            }
            if (chain != null) {
                if (tc == null) {
                    tc = TrustMaterial.DEFAULT;
                }
                Object[] trustManagers = tc.getTrustManagers();
                for (int i = 0; i < trustManagers.length; i++) {
                    JavaImpl.testTrust(trustManagers[i], chain, authType);
                }
            }
        } catch (Exception e) {
            return e;
        }
        return null;
    }

    private static Exception testHostname(SSLClient ssl) {
        try {
            X509Certificate[] chain = ssl.getCurrentServerChain();
            if (chain != null) {
                String hostName = target.host;
                HostnameVerifier.DEFAULT.check(hostName, chain[0]);
            }
        } catch (Exception e) {
            return e;
        }
        return null;
    }

    private static Exception testCRL(SSLClient ssl) {
        try {
            X509Certificate[] chain = ssl.getCurrentServerChain();
            if (chain != null) {
                for (int i = 0; i < chain.length; i++) {
                    Certificates.checkCRL(chain[i]);
                }
            }
        } catch (Exception e) {
            return e;
        }
        return null;
    }

    private static Exception testExpiry(SSLClient ssl) {
        try {
            X509Certificate[] chain = ssl.getCurrentServerChain();
            if (chain != null) {
                for (int i = 0; i < chain.length; i++) {
                    chain[i].checkValidity();
                }
            }
        } catch (Exception e) {
            return e;
        }
        return null;
    }


    public static class Arg implements Comparable {
        public final String shortArg;
        public final String longArg;
        public final String description;
        public final boolean isRequired;
        private final int id;

        public Arg(String s, String l, String d) {
            this(s, l, d, false);
        }

        public Arg(String s, String l, String d, boolean isRequired) {
            this.isRequired = isRequired;
            this.shortArg = s;
            this.longArg = l;
            this.description = d;
            this.id = args.size();
            args.add(this);
            if (s != null && s.length() >= 2) {
                argsMatch.put(s, this);
            }
            if (l != null && l.length() >= 3) {
                argsMatch.put(l, this);
            }
        }

        public int compareTo(Object o) {
            return id - ((Arg) o).id;
        }

        public String toString() {
            return shortArg + "/" + longArg;
        }
    }

    private static void parseArgs(String[] cargs) throws Exception {
        Map args = Util.parseArgs(cargs);
        Iterator it = args.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            Arg arg = (Arg) entry.getKey();
            String[] values = (String[]) entry.getValue();
            if (arg == ARG_TARGET) {
                target = Util.toAddress(values[0], 443);
                targetAddress = target.addr;
                targetPort = target.port;
            } else if (arg == ARG_BIND) {
                local = Util.toAddress(values[0], 443);
                localAddress = local.addr;
                localPort = local.port;
            } else if (arg == ARG_PROXY) {
                proxy = Util.toAddress(values[0], 80);
            } else if (arg == ARG_CLIENT_CERT) {
                clientCert = new File(values[0]);
            } else if (arg == ARG_CERT_CHAIN) {
                certChain = new File(values[0]);
            } else if (arg == ARG_PASSWORD) {
                password = values[0].toCharArray();
            } else if (arg == ARG_METHOD) {
                httpMethod = values[0].trim();
            } else if (arg == ARG_PATH) {
                path = values[0].trim();
            } else if (arg == ARG_HOST_HEADER) {
                hostHeader = values[0].trim();
            } else if (arg == ARG_TRUST_CERT) {
                for (int i = 0; i < values.length; i++) {
                    File f = new File(values[i]);
                    if (f.exists()) {
                        if (trustChain == null) {
                            trustChain = new TrustChain();
                        }
                        TrustMaterial tm = new TrustMaterial(f);
                        trustChain.addTrustMaterial(tm);
                    }
                }
            }
        }
        args.clear();
        for (int i = 0; i < cargs.length; i++) {
            cargs[i] = null;
        }

        if (targetAddress == null) {
            throw new IllegalArgumentException("\"" + ARG_TARGET + "\" is mandatory");
        }
    }
}
