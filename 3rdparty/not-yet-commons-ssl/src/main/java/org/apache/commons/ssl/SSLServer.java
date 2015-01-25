/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/SSLServer.java $
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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Properties;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since May 1, 2006
 */
public class SSLServer extends SSLServerSocketFactory {
    protected final SSL ssl;

    public SSLServer()
        throws GeneralSecurityException, IOException {
        this.ssl = new SSL();
        // client certs aren't usually tied down to a single host (and who knows
        // if the DNS reverse-lookup will work!).
        setCheckHostname(false);

        // If "javax.net.ssl.keyStore" is set, then we won't bother with this
        // silly SSLServer default behaviour.
        if (!ssl.usingSystemProperties) {
            // commons-ssl default KeyMaterial will be
            //  ~/.keystore with a password of "changeit".
            useDefaultKeyMaterial();
        }
    }

    private boolean useDefaultKeyMaterial()
        throws GeneralSecurityException, IOException {
        // If we're not able to re-use Tomcat's SSLServerSocket configuration,
        // commons-ssl default KeyMaterial will be  ~/.keystore with a password
        // of "changeit".
        Properties props = System.getProperties();
        boolean pwdSet = props.containsKey("javax.net.ssl.keyStorePassword");
        String pwd = props.getProperty("javax.net.ssl.keyStorePassword");
        pwd = pwdSet ? pwd : "changeit";

        String userHome = System.getProperty("user.home");
        String path = userHome + "/.keystore";
        File f = new File(path);
        boolean success = false;
        if (f.exists()) {
            KeyMaterial km = null;
            try {
                km = new KeyMaterial(path, pwd.toCharArray());
            }
            catch (Exception e) {
                // Don't want to blowup just because this silly default
                // behaviour didn't work out.
                if (pwdSet) {
                    // Buf if the user has specified a non-standard password for
                    // "javax.net.ssl.keyStorePassword", then we will warn them
                    // that things didn't work out.
                    System.err.println("commons-ssl automatic loading of [" + path + "] failed. ");
                    System.err.println(e);
                }
            }
            if (km != null) {
                setKeyMaterial(km);
                success = true;
            }
        }
        return success;
    }

    public void setDnsOverride(Map m) { ssl.setDnsOverride(m); }

    public void addTrustMaterial(TrustChain trustChain)
        throws NoSuchAlgorithmException, KeyStoreException,
        KeyManagementException, IOException, CertificateException {
        ssl.addTrustMaterial(trustChain);
    }

    public void setTrustMaterial(TrustChain trustChain)
        throws NoSuchAlgorithmException, KeyStoreException,
        KeyManagementException, IOException, CertificateException {
        ssl.setTrustMaterial(trustChain);
    }

    public void setKeyMaterial(KeyMaterial keyMaterial)
        throws NoSuchAlgorithmException, KeyStoreException,
        KeyManagementException, IOException, CertificateException {
        ssl.setKeyMaterial(keyMaterial);
    }

    public void setCheckCRL(boolean b) { ssl.setCheckCRL(b); }

    public void setCheckExpiry(boolean b) { ssl.setCheckExpiry(b); }

    public void setCheckHostname(boolean b) { ssl.setCheckHostname(b); }

    public void setConnectTimeout(int i) { ssl.setConnectTimeout(i); }

    public void setDefaultProtocol(String s) { ssl.setDefaultProtocol(s); }

    public void setEnabledCiphers(String[] ciphers) {
        ssl.setEnabledCiphers(ciphers);
    }

    public void setEnabledProtocols(String[] protocols) {
        ssl.setEnabledProtocols(protocols);
    }

    public void setHostnameVerifier(HostnameVerifier verifier) {
        ssl.setHostnameVerifier(verifier);
    }

    public void setSoTimeout(int soTimeout) { ssl.setSoTimeout(soTimeout); }

    public void setSSLWrapperFactory(SSLWrapperFactory wf) {
        ssl.setSSLWrapperFactory(wf);
    }

    public void setNeedClientAuth(boolean b) { ssl.setNeedClientAuth(b); }

    public void setWantClientAuth(boolean b) { ssl.setWantClientAuth(b); }

    public void setUseClientMode(boolean b) { ssl.setUseClientMode(b); }

    public X509Certificate[] getAssociatedCertificateChain() {
        return ssl.getAssociatedCertificateChain();
    }

    public boolean getCheckCRL() { return ssl.getCheckCRL(); }

    public boolean getCheckExpiry() { return ssl.getCheckExpiry(); }

    public boolean getCheckHostname() { return ssl.getCheckHostname(); }

    public int getConnectTimeout() { return ssl.getConnectTimeout(); }

    public String getDefaultProtocol() { return ssl.getDefaultProtocol(); }

    public String[] getEnabledCiphers() { return ssl.getEnabledCiphers(); }

    public String[] getEnabledProtocols() { return ssl.getEnabledProtocols(); }

    public HostnameVerifier getHostnameVerifier() {
        return ssl.getHostnameVerifier();
    }

    public int getSoTimeout() { return ssl.getSoTimeout(); }

    public SSLWrapperFactory getSSLWrapperFactory() {
        return ssl.getSSLWrapperFactory();
    }

    public boolean getNeedClientAuth() { return ssl.getNeedClientAuth(); }

    public boolean getWantClientAuth() { return ssl.getWantClientAuth(); }

    public boolean getUseClientMode() { /* SSLServer's default is false. */
        return !ssl.getUseClientModeDefault() && ssl.getUseClientMode();
    }

    public SSLContext getSSLContext() throws GeneralSecurityException, IOException {
        return ssl.getSSLContext();
    }

    public TrustChain getTrustChain() { return ssl.getTrustChain(); }

    public X509Certificate[] getCurrentClientChain() {
        return ssl.getCurrentClientChain();
    }

    public String[] getDefaultCipherSuites() {
        return ssl.getDefaultCipherSuites();
    }

    public String[] getSupportedCipherSuites() {
        return ssl.getSupportedCipherSuites();
    }

    public ServerSocket createServerSocket() throws IOException {
        return ssl.createServerSocket();
    }

    public ServerSocket createServerSocket(int port)
        throws IOException {
        return createServerSocket(port, 50);
    }

    public ServerSocket createServerSocket(int port, int backlog)
        throws IOException {
        return createServerSocket(port, backlog, null);
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
        return ssl.createServerSocket(port, backlog, localHost);
    }

}
