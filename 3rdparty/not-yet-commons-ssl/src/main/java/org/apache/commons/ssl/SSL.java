/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/SSL.java $
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

import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Not thread-safe.  (But who would ever share this thing across multiple
 * threads???)
 *
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since May 1, 2006
 */
public class SSL {
    private final static String[] KNOWN_PROTOCOLS =
            {"TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3", "SSLv2", "SSLv2Hello"};

    // SUPPORTED_CIPHERS_ARRAY is initialized in the static constructor.
    private final static String[] SUPPORTED_CIPHERS;

    public final static SortedSet KNOWN_PROTOCOLS_SET;
    public final static SortedSet SUPPORTED_CIPHERS_SET;

    static {
        TreeSet<String> ts = new TreeSet<String>(Collections.reverseOrder());
        ts.addAll(Arrays.asList(KNOWN_PROTOCOLS));
        KNOWN_PROTOCOLS_SET = Collections.unmodifiableSortedSet(ts);

        // SSLSocketFactory.getDefault() sometimes blocks on FileInputStream
        // reads of "/dev/random" (Linux only?).  You might find you system
        // stuck here.  Move the mouse around a little!
        SSLSocketFactory s = (SSLSocketFactory) SSLSocketFactory.getDefault();
        ts = new TreeSet<String>();
        SUPPORTED_CIPHERS = s.getSupportedCipherSuites();
        Arrays.sort(SUPPORTED_CIPHERS);
        ts.addAll(Arrays.asList(SUPPORTED_CIPHERS));
        SUPPORTED_CIPHERS_SET = Collections.unmodifiableSortedSet(ts);
    }

    private Object sslContext = null;
    private int initCount = 0;
    private SSLSocketFactory socketFactory = null;
    private SSLServerSocketFactory serverSocketFactory = null;
    private HostnameVerifier hostnameVerifier = HostnameVerifier.DEFAULT;
    private boolean isSecure = true;  // if false, the client-style operations only create plain sockets.
    private boolean checkHostname = true;
    private boolean checkCRL = true;
    private boolean checkExpiry = true;
    private boolean useClientMode = false;
    private boolean useClientModeDefault = true;
    private int soTimeout = 24 * 60 * 60 * 1000; // default: one day
    private int connectTimeout = 60 * 60 * 1000; // default: one hour
    private TrustChain trustChain = null;
    private KeyMaterial keyMaterial = null;
    private String[] enabledCiphers = null;
    private String[] enabledProtocols = null;
    private String defaultProtocol = "TLS";
    private X509Certificate[] currentServerChain;
    private X509Certificate[] currentClientChain;
    private boolean wantClientAuth = true;
    private boolean needClientAuth = false;
    private SSLWrapperFactory sslWrapperFactory = SSLWrapperFactory.NO_WRAP;
    private Map dnsOverride;

    protected final boolean usingSystemProperties;

    public SSL()
            throws GeneralSecurityException, IOException {
        boolean usingSysProps = false;
        Properties props = System.getProperties();
        boolean ksSet = props.containsKey("javax.net.ssl.keyStore");
        boolean tsSet = props.containsKey("javax.net.ssl.trustStore");
        if (ksSet) {
            String path = System.getProperty("javax.net.ssl.keyStore");
            String pwd = System.getProperty("javax.net.ssl.keyStorePassword");
            pwd = pwd != null ? pwd : ""; // JSSE default is "".
            File f = new File(path);
            if (f.exists()) {
                KeyMaterial km = new KeyMaterial(path, pwd.toCharArray());
                setKeyMaterial(km);
                usingSysProps = true;
            }
        }
        boolean trustMaterialSet = false;
        if (tsSet) {
            String path = System.getProperty("javax.net.ssl.trustStore");
            String pwd = System.getProperty("javax.net.ssl.trustStorePassword");
            boolean pwdWasNull = pwd == null;
            pwd = pwdWasNull ? "" : pwd; // JSSE default is "".
            File f = new File(path);
            if (f.exists()) {
                TrustMaterial tm;
                try {
                    tm = new TrustMaterial(path, pwd.toCharArray());
                }
                catch (GeneralSecurityException gse) {
                    // Probably a bad password.  If we're using the default password,
                    // let's try and survive this setback.
                    if (pwdWasNull) {
                        tm = new TrustMaterial(path);
                    } else {
                        throw gse;
                    }
                }

                setTrustMaterial(tm);
                usingSysProps = true;
                trustMaterialSet = true;
            }
        }

        /*
            No default trust material was set.  We'll use the JSSE standard way
            where we test for "JSSE_CACERTS" first, and then fall back on
            "CACERTS".  We could just leave TrustMaterial null, but then our
            setCheckCRL() and setCheckExpiry() features won't work.  We need a
            non-null TrustMaterial object in order to intercept and decorate
            the JVM's default TrustManager.
          */
        if (!trustMaterialSet) {
            setTrustMaterial(TrustMaterial.DEFAULT);
        }
        this.usingSystemProperties = usingSysProps;
        dirtyAndReloadIfYoung();
    }

    private void dirty() {
        this.sslContext = null;
        this.socketFactory = null;
        this.serverSocketFactory = null;
    }

    private void dirtyAndReloadIfYoung()
            throws NoSuchAlgorithmException, KeyStoreException,
            KeyManagementException, IOException, CertificateException {
        dirty();
        if (initCount >= 0 && initCount <= 5) {
            // The first five init's we do early (before any sockets are
            // created) in the hope that will trigger any explosions nice
            // and early, with the correct exception type.

            // After the first five init's, we revert to a regular
            // dirty / init pattern, and the "init" happens very late:
            // just before the socket is created.  If badness happens, a
            // wrapping RuntimeException will be thrown.
            init();
        }
    }

    String dnsOverride(String host) {
        if (dnsOverride != null && dnsOverride.containsKey(host)) {
            String override = (String) dnsOverride.get(host);
            if (override != null && !"".equals(override.trim())) {
                return override;
            }
        }
        return host;
    }

    public void setDnsOverride(Map m) {
        this.dnsOverride = m;
    }

    public void setIsSecure(boolean b) {
        this.isSecure = b;
    }

    public boolean isSecure() {
        return isSecure;
    }

    public SSLContext getSSLContext()
            throws GeneralSecurityException, IOException

    {
        Object obj = getSSLContextAsObject();
        return (SSLContext) obj;
    }

    /**
     * @return com.sun.net.ssl.SSLContext or javax.net.ssl.SSLContext depending
     *         on the JSSE implementation we're using.
     * @throws java.security.GeneralSecurityException problem creating SSLContext
     * @throws java.io.IOException              problem creating SSLContext
     */
    public Object getSSLContextAsObject()
            throws GeneralSecurityException, IOException

    {
        if (sslContext == null) {
            init();
        }
        return sslContext;
    }

    public void addTrustMaterial(TrustChain trustChain)
            throws NoSuchAlgorithmException, KeyStoreException,
            KeyManagementException, IOException, CertificateException {
        if (this.trustChain == null || trustChain == TrustMaterial.TRUST_ALL) {
            this.trustChain = trustChain;
        } else {
            this.trustChain.addTrustMaterial(trustChain);
        }
        dirtyAndReloadIfYoung();
    }

    public void setTrustMaterial(TrustChain trustChain)
            throws NoSuchAlgorithmException, KeyStoreException,
            KeyManagementException, IOException, CertificateException {
        this.trustChain = trustChain;
        dirtyAndReloadIfYoung();
    }

    public void setKeyMaterial(KeyMaterial keyMaterial)
            throws NoSuchAlgorithmException, KeyStoreException,
            KeyManagementException, IOException, CertificateException {
        this.keyMaterial = keyMaterial;
        dirtyAndReloadIfYoung();
    }

    public X509Certificate[] getAssociatedCertificateChain() {
        if (keyMaterial != null) {
            List list = keyMaterial.getAssociatedCertificateChains();
            return (X509Certificate[]) list.get(0);
        } else {
            return null;
        }
    }

    public String[] getEnabledCiphers() {
        return enabledCiphers != null ? enabledCiphers : getDefaultCipherSuites();
    }

    public void setEnabledCiphers(String[] ciphers) {
        HashSet<String> desired = new HashSet<String>(Arrays.asList(ciphers));
        desired.removeAll(SUPPORTED_CIPHERS_SET);
        if (!desired.isEmpty()) {
            throw new IllegalArgumentException("following ciphers not supported: " + desired);
        }
        this.enabledCiphers = ciphers;
    }

    public String[] getEnabledProtocols() {
        return enabledProtocols;
    }

    public void setEnabledProtocols(String[] protocols) {
        this.enabledProtocols = protocols;
    }

    public String getDefaultProtocol() {
        return defaultProtocol;
    }

    public void setDefaultProtocol(String protocol) {
        this.defaultProtocol = protocol;
        dirty();
    }

    public boolean getCheckHostname() {
        return checkHostname;
    }

    public void setCheckHostname(boolean checkHostname) {
        this.checkHostname = checkHostname;
    }

    public void setHostnameVerifier(HostnameVerifier verifier) {
        if (verifier == null) {
            verifier = HostnameVerifier.DEFAULT;
        }
        this.hostnameVerifier = verifier;
    }

    public HostnameVerifier getHostnameVerifier() {
        return hostnameVerifier;
    }

    public boolean getCheckCRL() {
        return checkCRL;
    }

    public void setCheckCRL(boolean checkCRL) {
        this.checkCRL = checkCRL;
    }

    public boolean getCheckExpiry() {
        return checkExpiry;
    }

    public void setCheckExpiry(boolean checkExpiry) {
        this.checkExpiry = checkExpiry;
    }

    public void setSoTimeout(int soTimeout) {
        if (soTimeout < 0) {
            throw new IllegalArgumentException("soTimeout must not be negative");
        }
        this.soTimeout = soTimeout;
    }

    public int getSoTimeout() {
        return soTimeout;
    }

    public void setConnectTimeout(int connectTimeout) {
        if (connectTimeout < 0) {
            throw new IllegalArgumentException("connectTimeout must not be negative");
        }
        this.connectTimeout = connectTimeout;
    }

    public void setUseClientMode(boolean useClientMode) {
        this.useClientModeDefault = false;
        this.useClientMode = useClientMode;
    }

    public boolean getUseClientModeDefault() {
        return useClientModeDefault;
    }

    public boolean getUseClientMode() {
        return useClientMode;
    }

    public void setWantClientAuth(boolean wantClientAuth) {
        this.wantClientAuth = wantClientAuth;
    }

    public void setNeedClientAuth(boolean needClientAuth) {
        this.needClientAuth = needClientAuth;
    }

    public boolean getWantClientAuth() {
        return wantClientAuth;
    }

    public boolean getNeedClientAuth() {
        return needClientAuth;
    }

    public SSLWrapperFactory getSSLWrapperFactory() {
        return this.sslWrapperFactory;
    }

    public void setSSLWrapperFactory(SSLWrapperFactory wf) {
        this.sslWrapperFactory = wf;
    }

    private void initThrowRuntime() {
        try {
            init();
        }
        catch (GeneralSecurityException gse) {
            throw JavaImpl.newRuntimeException(gse);
        }
        catch (IOException ioe) {
            throw JavaImpl.newRuntimeException(ioe);
        }
    }

    private void init()
            throws NoSuchAlgorithmException, KeyStoreException,
            KeyManagementException, IOException, CertificateException {
        socketFactory = null;
        serverSocketFactory = null;
        this.sslContext = JavaImpl.init(this, trustChain, keyMaterial);
        initCount++;
    }

    public void doPreConnectSocketStuff(Socket s) throws IOException {
        if (s instanceof SSLSocket && !useClientModeDefault) {
            ((SSLSocket) s).setUseClientMode(useClientMode);
        }
        if (soTimeout > 0) {
            s.setSoTimeout(soTimeout);
        }
        if (s instanceof SSLSocket) {
            if (enabledProtocols != null) {
                JavaImpl.setEnabledProtocols(s, enabledProtocols);
            }
            if (enabledCiphers != null) {
                ((SSLSocket) s).setEnabledCipherSuites(enabledCiphers);
            }
        }
    }

    public void doPostConnectSocketStuff(Socket s, String host)
            throws IOException {
        if (checkHostname && s instanceof SSLSocket) {
            hostnameVerifier.check(host, (SSLSocket) s);
        }
    }

    public Socket createSocket() throws IOException {
        if (isSecure) {
            return sslWrapperFactory.wrap(JavaImpl.createSocket(this));
        } else {
            Socket s = SocketFactory.getDefault().createSocket();
            doPreConnectSocketStuff(s);
            return s;
        }
    }

    /**
     * Attempts to get a new socket connection to the given host within the
     * given time limit.
     *
     * @param remoteHost the host name/IP
     * @param remotePort the port on the host
     * @param localHost  the local host name/IP to bind the socket to
     * @param localPort  the port on the local machine
     * @param timeout    the connection timeout (0==infinite)
     * @return Socket a new socket
     * @throws java.io.IOException          if an I/O error occurs while creating the socket
     * @throws java.net.UnknownHostException if the IP address of the host cannot be
     *                              determined
     */
    public Socket createSocket(
            String remoteHost, int remotePort, InetAddress localHost, int localPort, int timeout
    ) throws IOException {
        // Only use our factory-wide connectTimeout if this method was passed
        // in a timeout of 0 (infinite).
        int factoryTimeout = getConnectTimeout();
        int connectTimeout = timeout == 0 ? factoryTimeout : timeout;
        Socket s;
        if (isSecure) {
            s = JavaImpl.createSocket(
                    this, remoteHost, remotePort, localHost, localPort, connectTimeout
            );
        } else {
            s = JavaImpl.createPlainSocket(
                    this, remoteHost, remotePort, localHost, localPort, connectTimeout
            );
        }
        return sslWrapperFactory.wrap(s);
    }

    public Socket createSocket(
            Socket s, String remoteHost, int remotePort, boolean autoClose
    ) throws IOException {
        SSLSocketFactory sf = getSSLSocketFactory();
        s = sf.createSocket(s, remoteHost, remotePort, autoClose);
        doPreConnectSocketStuff(s);
        doPostConnectSocketStuff(s, remoteHost);
        return sslWrapperFactory.wrap(s);
    }

    public ServerSocket createServerSocket() throws IOException {
        SSLServerSocket ss = JavaImpl.createServerSocket(this);
        return getSSLWrapperFactory().wrap(ss, this);
    }

    /**
     * Attempts to get a new socket connection to the given host within the
     * given time limit.
     *
     * @param localHost the local host name/IP to bind against (null == ANY)
     * @param port      the port to listen on
     * @param backlog   number of connections allowed to queue up for accept().
     * @return SSLServerSocket a new server socket
     * @throws java.io.IOException if an I/O error occurs while creating thesocket
     */
    public ServerSocket createServerSocket(int port, int backlog,
                                           InetAddress localHost)
            throws IOException {
        SSLServerSocketFactory f = getSSLServerSocketFactory();
        ServerSocket ss = f.createServerSocket(port, backlog, localHost);
        SSLServerSocket s = (SSLServerSocket) ss;
        doPreConnectServerSocketStuff(s);
        return getSSLWrapperFactory().wrap(s, this);
    }

    public void doPreConnectServerSocketStuff(SSLServerSocket s)
            throws IOException {
        if (soTimeout > 0) {
            s.setSoTimeout(soTimeout);
        }
        if (enabledProtocols != null) {
            JavaImpl.setEnabledProtocols(s, enabledProtocols);
        }
        if (enabledCiphers != null) {
            s.setEnabledCipherSuites(enabledCiphers);
        }

        /*
          setNeedClientAuth( false ) has an annoying side effect:  it seems to
          reset setWantClient( true ) back to to false.  So I do things this
          way to make sure setting things "true" happens after setting things
          "false" - giving "true" priority.
          */
        if (!wantClientAuth) {
            JavaImpl.setWantClientAuth(s, false);
        }
        if (!needClientAuth) {
            s.setNeedClientAuth(false);
        }
        if (wantClientAuth) {
            JavaImpl.setWantClientAuth(s, true);
        }
        if (needClientAuth) {
            s.setNeedClientAuth(true);
        }
    }

    public SSLSocketFactory getSSLSocketFactory() {
        if (sslContext == null) {
            initThrowRuntime();
        }
        if (socketFactory == null) {
            socketFactory = JavaImpl.getSSLSocketFactory(sslContext);
        }
        return socketFactory;
    }

    public SSLServerSocketFactory getSSLServerSocketFactory() {
        if (sslContext == null) {
            initThrowRuntime();
        }
        if (serverSocketFactory == null) {
            serverSocketFactory = JavaImpl.getSSLServerSocketFactory(sslContext);
        }
        return serverSocketFactory;
    }

    public int getConnectTimeout() {
        return connectTimeout;
    }

    public String[] getDefaultCipherSuites() {
        return getSSLSocketFactory().getDefaultCipherSuites();
    }

    public String[] getSupportedCipherSuites() {
        String[] s = new String[SUPPORTED_CIPHERS.length];
        System.arraycopy(SUPPORTED_CIPHERS, 0, s, 0, s.length);
        return s;
    }

    public TrustChain getTrustChain() {
        return trustChain;
    }

    public void setCurrentServerChain(X509Certificate[] chain) {
        this.currentServerChain = chain;
    }

    public void setCurrentClientChain(X509Certificate[] chain) {
        this.currentClientChain = chain;
    }

    public X509Certificate[] getCurrentServerChain() {
        return currentServerChain;
    }

    public X509Certificate[] getCurrentClientChain() {
        return currentClientChain;
    }
}
