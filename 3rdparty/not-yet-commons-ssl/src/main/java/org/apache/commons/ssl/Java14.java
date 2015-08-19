/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/Java14.java $
 * $Revision: 166 $
 * $Date: 2014-04-28 11:40:25 -0700 (Mon, 28 Apr 2014) $
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

import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
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
public final class Java14 extends JavaImpl {
    private static Java14 instance = new Java14();

    private Java14() {
        try {
            SSLSocketFactory.getDefault().createSocket();
        }
        catch (IOException ioe) {
            ioe.hashCode();
        }
    }

    public static Java14 getInstance() {
        return instance;
    }

    public final String getVersion() {
        return "Java14";
    }

    protected final String retrieveSubjectX500(X509Certificate cert) {
        return cert.getSubjectX500Principal().toString();
    }

    protected final String retrieveIssuerX500(X509Certificate cert) {
        return cert.getIssuerX500Principal().toString();
    }

    protected final Certificate[] retrievePeerCerts(SSLSession sslSession)
        throws SSLPeerUnverifiedException {
        return sslSession.getPeerCertificates();
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
        return new RuntimeException(cause);
    }

    protected final SSLSocket buildSocket(SSL ssl) throws IOException {
        SSLSocketFactory sf = ssl.getSSLSocketFactory();
        SSLSocket s = (SSLSocket) sf.createSocket();
        ssl.doPreConnectSocketStuff(s);
        return s;
    }

    protected final SSLSocket buildSocket(SSL ssl, String remoteHost,
                                          int remotePort, InetAddress localHost,
                                          int localPort, int timeout)
        throws IOException {
        SSLSocket s = buildSocket(ssl);
        s = (SSLSocket) connectSocket(s, null, remoteHost, remotePort,
            localHost, localPort, timeout, ssl);
        ssl.doPostConnectSocketStuff(s, remoteHost);
        return s;
    }


    protected final Socket buildPlainSocket(
            SSL ssl, String remoteHost, int remotePort, InetAddress localHost, int localPort, int timeout
    ) throws IOException {
        Socket s = SocketFactory.getDefault().createSocket();
        ssl.doPreConnectSocketStuff(s);
        s = connectSocket(
                s, null, remoteHost, remotePort, localHost, localPort, timeout, ssl
        );
        ssl.doPostConnectSocketStuff(s, remoteHost);
        return s;
    }

    protected final Socket connectSocket(Socket s, SocketFactory sf,
                                         String host, int remotePort,
                                         InetAddress localHost, int localPort,
                                         int timeout, SSL ssl)
        throws IOException {
        if (s == null) {
            if (sf == null) {
                s = new Socket();
            } else {
                s = sf.createSocket();
            }
        }
        host = ssl.dnsOverride(host);
        InetAddress remoteHost = Util.toInetAddress(host);
        InetSocketAddress dest = new InetSocketAddress(remoteHost, remotePort);
        InetSocketAddress src = new InetSocketAddress(localHost, localPort);
        s.bind(src);
        s.connect(dest, timeout);
        return s;
    }

    protected final SSLServerSocket buildServerSocket(SSL ssl)
        throws IOException {
        ServerSocket s = ssl.getSSLServerSocketFactory().createServerSocket();
        SSLServerSocket ss = (SSLServerSocket) s;
        ssl.doPreConnectServerSocketStuff(ss);
        return ss;
    }

    protected final void wantClientAuth(Object o, boolean wantClientAuth) {
        SSLSocket s;
        SSLServerSocket ss;
        if (o instanceof SSLSocket) {
            s = (SSLSocket) o;
            s.setWantClientAuth(wantClientAuth);
        } else if (o instanceof SSLServerSocket) {
            ss = (SSLServerSocket) o;
            ss.setWantClientAuth(wantClientAuth);
        } else {
            throw new ClassCastException("need SSLSocket or SSLServerSocket");
        }
    }

    protected final void enabledProtocols(Object o, String[] enabledProtocols) {
        SSLSocket s;
        SSLServerSocket ss;
        if (o instanceof SSLSocket) {
            s = (SSLSocket) o;
            s.setEnabledProtocols(enabledProtocols);
        } else if (o instanceof SSLServerSocket) {
            ss = (SSLServerSocket) o;
            ss.setEnabledProtocols(enabledProtocols);
        } else {
            throw new ClassCastException("need SSLSocket or SSLServerSocket");
        }
    }

    protected void checkTrusted(Object trustManager, X509Certificate[] chain,
                                String authType)
        throws CertificateException {
        X509TrustManager tm = (X509TrustManager) trustManager;
        tm.checkServerTrusted(chain, authType);
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
                    keyManagers[i] = new Java14KeyManagerWrapper(km, k, ssl);
                }
            }
        }
        if (trustManagers != null) {
            for (int i = 0; i < trustManagers.length; i++) {
                if (trustManagers[i] instanceof X509TrustManager) {
                    X509TrustManager tm = (X509TrustManager) trustManagers[i];
                    trustManagers[i] = new Java14TrustManagerWrapper(tm, tc, ssl);
                }
            }
        }
        context.init(keyManagers, trustManagers, null);
        return context;
    }


}
