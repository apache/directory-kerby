/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/Java13.java $
 * $Revision: 155 $
 * $Date: 2009-09-17 14:00:58 -0700 (Thu, 17 Sep 2009) $
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

import com.sun.net.ssl.KeyManager;
import com.sun.net.ssl.KeyManagerFactory;
import com.sun.net.ssl.SSLContext;
import com.sun.net.ssl.TrustManager;
import com.sun.net.ssl.TrustManagerFactory;
import com.sun.net.ssl.X509KeyManager;
import com.sun.net.ssl.X509TrustManager;

import javax.net.SocketFactory;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 30-Jun-2006
 */
public final class Java13 extends JavaImpl {
    private final static Java13 instance = new Java13();

    private Java13() {
        try {
            Class c = Class.forName("javax.crypto.Cipher");
            Class[] sig = {String.class};
            String[] args = {"DES/CBC/PKCS5Padding"};
            Method m = c.getMethod("getInstance", sig);
            m.invoke(null, (Object[]) args);
        }
        catch (Exception e) {
            try {
                Class c = Class.forName("com.sun.crypto.provider.SunJCE");
                Security.addProvider((Provider) c.newInstance());
                // System.out.println( "jce not loaded: " + e + " - loading SunJCE!" );
                //e.printStackTrace( System.out );
            }
            catch (Exception e2) {
                System.out.println("com.sun.crypto.provider.SunJCE unavailable: " + e2);
                // e2.printStackTrace( System.out );
            }
        }
        try {
            URL u = new URL("https://vancity.com/");
            u.openConnection();
        }
        catch (Exception e) {
            // System.out.println( "java.net.URL support of https not loaded: " + e + " - attempting to load com.sun.net.ssl.internal.ssl.Provider!" );
            Security.addProvider(new com.sun.net.ssl.internal.ssl.Provider());
            System.setProperty("java.protocol.handler.pkgs", "com.sun.net.ssl.internal.www.protocol");
        }
        // System.out.println( "old HANDLER: " + HANDLER );
    }

    public static Java13 getInstance() {
        return instance;
    }

    public final String getVersion() {
        return "Java13";
    }

    protected final String retrieveSubjectX500(X509Certificate cert) {
        return cert.getSubjectDN().toString();
    }

    protected final String retrieveIssuerX500(X509Certificate cert) {
        return cert.getIssuerDN().toString();
    }

    protected final Certificate[] retrievePeerCerts(SSLSession sslSession)
        throws SSLPeerUnverifiedException {
        javax.security.cert.X509Certificate[] chain;
        chain = sslSession.getPeerCertificateChain();
        X509Certificate[] newChain = new X509Certificate[chain.length];
        try {
            for (int i = 0; i < chain.length; i++) {
                javax.security.cert.X509Certificate javaxCert = chain[i];
                byte[] encoded = javaxCert.getEncoded();
                ByteArrayInputStream in = new ByteArrayInputStream(encoded);
                synchronized (Certificates.CF) {
                    Certificate c = Certificates.CF.generateCertificate(in);
                    newChain[i] = (X509Certificate) c;
                }
            }
        }
        catch (Exception e) {
            throw buildRuntimeException(e);
        }
        return newChain;
    }

    protected final Object buildKeyManagerFactory(KeyStore ks, char[] password)
        throws NoSuchAlgorithmException, KeyStoreException,
        UnrecoverableKeyException {
        String alg = KeyManagerFactory.getDefaultAlgorithm();
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(alg);
        kmf.init(ks, password);
        return kmf;
    }

    protected final Object buildTrustManagerFactory(KeyStore ks)
        throws NoSuchAlgorithmException, KeyStoreException {
        String alg = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(alg);
        tmf.init(ks);
        return tmf;
    }


    protected final Object[] retrieveKeyManagers(Object keyManagerFactory) {
        KeyManagerFactory kmf = (KeyManagerFactory) keyManagerFactory;
        return kmf.getKeyManagers();
    }

    protected final Object[] retrieveTrustManagers(Object trustManagerFactory) {
        TrustManagerFactory tmf = (TrustManagerFactory) trustManagerFactory;
        return tmf.getTrustManagers();
    }

    protected final SSLSocketFactory buildSSLSocketFactory(Object ssl) {
        return ((SSLContext) ssl).getSocketFactory();
    }

    protected final SSLServerSocketFactory buildSSLServerSocketFactory(Object ssl) {
        return ((SSLContext) ssl).getServerSocketFactory();
    }

    protected final RuntimeException buildRuntimeException(Exception cause) {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream(512);
        PrintStream ps = new PrintStream(byteOut);
        ps.println(cause.toString());
        cause.printStackTrace(ps);
        ps.flush();
        String originalCause = byteOut.toString();
        return new RuntimeException(originalCause);
    }

    protected final SSLSocket buildSocket(SSL ssl) {
        // Not supported in Java 1.3.
        throw new UnsupportedOperationException();
    }

    protected final SSLSocket buildSocket(SSL ssl, String remoteHost,
                                          int remotePort, InetAddress localHost,
                                          int localPort, int connectTimeout)
        throws IOException {
        // Connect Timeout ignored for Java 1.3
        SSLSocketFactory sf = ssl.getSSLSocketFactory();
        SSLSocket s = (SSLSocket) connectSocket(
                null, sf, remoteHost, remotePort, localHost, localPort, -1, ssl
        );
        ssl.doPreConnectSocketStuff(s);
        ssl.doPostConnectSocketStuff(s, remoteHost);
        return s;
    }

    protected final Socket buildPlainSocket(
            SSL ssl, String remoteHost, int remotePort, InetAddress localHost, int localPort, int connectTimeout
    )
        throws IOException {
        // Connect Timeout ignored for Java 1.3
        SocketFactory sf = SocketFactory.getDefault();
        Socket s = connectSocket(
                null, sf, remoteHost, remotePort, localHost, localPort, -1, ssl
        );
        ssl.doPreConnectSocketStuff(s);
        ssl.doPostConnectSocketStuff(s, remoteHost);
        return s;
    }
    
    protected final Socket connectSocket(Socket s, SocketFactory sf,
                                         String remoteHost, int remotePort,
                                         InetAddress localHost, int localPort,
                                         int timeout, SSL ssl)
        throws IOException {

        remoteHost = ssl.dnsOverride(remoteHost);

        // Connect Timeout ignored for Java 1.3
        if (s == null) {
            if (sf == null) {
                s = new Socket(remoteHost, remotePort, localHost, localPort);
            } else {
                s = sf.createSocket(remoteHost, remotePort, localHost, localPort);
            }
        }
        return s;
    }


    protected final SSLServerSocket buildServerSocket(SSL ssl) {
        // Not supported in Java 1.3.
        throw new UnsupportedOperationException();
    }

    protected final void wantClientAuth(Object o, boolean wantClientAuth) {
        // Not supported in Java 1.3.
    }

    protected final void enabledProtocols(Object o, String[] enabledProtocols) {
        // Not supported in Java 1.3.
    }

    protected void checkTrusted(Object trustManager, X509Certificate[] chain,
                                String authType)
        throws CertificateException {
        X509TrustManager tm = (X509TrustManager) trustManager;
        boolean result = tm.isServerTrusted(chain);
        if (!result) {
            throw new CertificateException("commons-ssl java13 mode: certificate chain not trusted");
        }
    }


    protected final Object initSSL(SSL ssl, TrustChain tc, KeyMaterial k)
        throws NoSuchAlgorithmException, KeyStoreException,
        CertificateException, KeyManagementException, IOException {
        SSLContext context = SSLContext.getInstance(ssl.getDefaultProtocol());
        TrustManager[] trustManagers = null;
        KeyManager[] keyManagers = null;
        if (tc != null) {
            trustManagers = (TrustManager[]) tc.getTrustManagers();
        }
        if (k != null) {
            keyManagers = (KeyManager[]) k.getKeyManagers();
        }
        if (keyManagers != null) {
            for (int i = 0; i < keyManagers.length; i++) {
                if (keyManagers[i] instanceof X509KeyManager) {
                    X509KeyManager km = (X509KeyManager) keyManagers[i];
                    keyManagers[i] = new Java13KeyManagerWrapper(km, k, ssl);
                }
            }
        }
        if (trustManagers != null) {
            for (int i = 0; i < trustManagers.length; i++) {
                if (trustManagers[i] instanceof X509TrustManager) {
                    X509TrustManager tm = (X509TrustManager) trustManagers[i];
                    trustManagers[i] = new Java13TrustManagerWrapper(tm, tc, ssl);
                }
            }
        }
        context.init(keyManagers, trustManagers, null);
        return context;
    }


}
