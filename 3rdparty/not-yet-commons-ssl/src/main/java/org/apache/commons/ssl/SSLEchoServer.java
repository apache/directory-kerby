/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/SSLEchoServer.java $
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

package org.apache.commons.ssl;

import org.apache.commons.ssl.util.ReadLine;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 2-May-2006
 */
public class SSLEchoServer {

    public static void main(String[] args) throws Exception {
        int port = 7443;
        if (args.length >= 1) {
            port = Integer.parseInt(args[0]);
        }

        SSLServer ssl = new SSLServer();
        ssl.setTrustMaterial(TrustMaterial.TRUST_ALL);
        ssl.setCheckExpiry(false);
        ssl.setCheckCRL(false);
        ssl.setCheckHostname(false);
        ssl.setWantClientAuth(true);

        SSLServerSocket ss = (SSLServerSocket) ssl.createServerSocket(port, 3);
        System.out.println("SSL Echo server listening on port: " + port);
        while (true) {
            SSLSocket s = (SSLSocket) ss.accept();
            s.setSoTimeout(30000);
            EchoRunnable r = new EchoRunnable(s);
            new Thread(r).start();
        }

    }

    public static class EchoRunnable implements Runnable {
        private SSLSocket s;

        public EchoRunnable(SSLSocket s) {
            this.s = s;
        }

        public void run() {
            InputStream in = null;
            OutputStream out = null;
            System.out.println("Socket accepted!");
            try {
                SSLSession session = s.getSession();

                try {
                    Certificate[] certs = JavaImpl.getPeerCertificates(session);
                    if (certs != null) {
                        for (int i = 0; i < certs.length; i++) {
                            // log client cert info
                            X509Certificate cert = (X509Certificate) certs[i];
                            String s = "client cert " + i + ":";
                            s += JavaImpl.getSubjectX500(cert);
                            System.out.println(s);
                            System.out.println(Certificates.toString(cert));
                        }
                    }
                } catch (SSLPeerUnverifiedException sslpue) {
                    // oh well, no client cert for us
                    System.out.println(sslpue);
                }

                in = s.getInputStream();
                out = s.getOutputStream();
                ReadLine readLine = new ReadLine(in);
                String line = readLine.next();
                if (line != null && line.indexOf("HTTP") > 0) {
                    out.write("HTTP/1.1 200 OK\r\n\r\n".getBytes());
                    out.flush();
                }
                while (line != null) {
                    String echo = "ECHO:>" + line + "\n";
                    out.write(echo.getBytes());
                    out.flush();
                    line = readLine.next();
                }
            } catch (IOException ioe) {
                try {
                    if (out != null) {
                        out.close();
                    }
                    if (in != null) {
                        in.close();
                    }
                    s.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                if (ioe instanceof InterruptedIOException) {
                    System.out.println("Socket closed after 30 second timeout.");
                } else {
                    ioe.printStackTrace();
                }

            }
        }
    }

}
