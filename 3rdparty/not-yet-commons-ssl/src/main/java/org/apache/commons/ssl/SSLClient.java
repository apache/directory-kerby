/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/SSLClient.java $
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
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 27-Feb-2006
 */
public class SSLClient extends SSLSocketFactory {
    private final SSL ssl;

    public SSLClient()
        throws GeneralSecurityException, IOException {
        this.ssl = new SSL();
    }

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

    public void setIsSecure(boolean b) {
        ssl.setIsSecure(b);
    }

    public void setDnsOverride(Map m) {
        ssl.setDnsOverride(m);
    }

    public void setCheckCRL(boolean b) {
        ssl.setCheckCRL(b);
    }

    public void setCheckExpiry(boolean b) {
        ssl.setCheckExpiry(b);
    }

    public void setCheckHostname(boolean b) {
        ssl.setCheckHostname(b);
    }

    public void setConnectTimeout(int i) {
        ssl.setConnectTimeout(i);
    }

    public void setDefaultProtocol(String s) {
        ssl.setDefaultProtocol(s);
    }

    public void setEnabledCiphers(String[] ciphers) {
        ssl.setEnabledCiphers(ciphers);
    }

    public void setEnabledProtocols(String[] protocols) {
        ssl.setEnabledProtocols(protocols);
    }

    public void setHostnameVerifier(HostnameVerifier verifier) {
        ssl.setHostnameVerifier(verifier);
    }

    public void setSoTimeout(int soTimeout) {
        ssl.setSoTimeout(soTimeout);
    }

    public void setSSLWrapperFactory(SSLWrapperFactory wf) {
        ssl.setSSLWrapperFactory(wf);
    }

    public void setNeedClientAuth(boolean b) {
        ssl.setNeedClientAuth(b);
    }

    public void setWantClientAuth(boolean b) {
        ssl.setWantClientAuth(b);
    }

    public void setUseClientMode(boolean b) {
        ssl.setUseClientMode(b);
    }

    public boolean isSecure() {
        return ssl.isSecure();
    }

    public X509Certificate[] getAssociatedCertificateChain() {
        return ssl.getAssociatedCertificateChain();
    }

    public boolean getCheckCRL() {
        return ssl.getCheckCRL();
    }

    public boolean getCheckExpiry() {
        return ssl.getCheckExpiry();
    }

    public boolean getCheckHostname() {
        return ssl.getCheckHostname();
    }

    public int getConnectTimeout() {
        return ssl.getConnectTimeout();
    }

    public String getDefaultProtocol() {
        return ssl.getDefaultProtocol();
    }

    public String[] getEnabledCiphers() {
        return ssl.getEnabledCiphers();
    }

    public String[] getEnabledProtocols() {
        return ssl.getEnabledProtocols();
    }

    public HostnameVerifier getHostnameVerifier() {
        return ssl.getHostnameVerifier();
    }

    public int getSoTimeout() {
        return ssl.getSoTimeout();
    }

    public SSLWrapperFactory getSSLWrapperFactory() {
        return ssl.getSSLWrapperFactory();
    }

    public boolean getNeedClientAuth() {
        return ssl.getNeedClientAuth();
    }

    public boolean getWantClientAuth() {
        return ssl.getWantClientAuth();
    }

    public boolean getUseClientMode() { /* SSLClient's default is true. */
        return ssl.getUseClientModeDefault() || ssl.getUseClientMode();
    }

    public SSLContext getSSLContext() throws GeneralSecurityException, IOException {
        return ssl.getSSLContext();
    }

    public TrustChain getTrustChain() {
        return ssl.getTrustChain();
    }

    public X509Certificate[] getCurrentServerChain() {
        return ssl.getCurrentServerChain();
    }

    public String[] getDefaultCipherSuites() {
        return ssl.getDefaultCipherSuites();
    }

    public String[] getSupportedCipherSuites() {
        return ssl.getSupportedCipherSuites();
    }

    public Socket createSocket() throws IOException {
        return ssl.createSocket();
    }

    public Socket createSocket(String host, int port)
        throws IOException {
        return createSocket(host, port, null, 0);
    }

    public Socket createSocket(InetAddress host, int port)
        throws IOException {
        return createSocket(host.getHostName(), port);
    }

    public Socket createSocket(InetAddress host, int port,
                               InetAddress localHost, int localPort)
        throws IOException {
        return createSocket(host.getHostName(), port, localHost, localPort);
    }

    public Socket createSocket(String host, int port,
                               InetAddress localHost, int localPort)
        throws IOException {
        return createSocket(host, port, localHost, localPort, 0);
    }

    /**
     * Attempts to get a new socket connection to the given host within the
     * given time limit.
     *
     * @param host      the host name/IP
     * @param port      the port on the host
     * @param localHost the local host name/IP to bind the socket to
     * @param localPort the port on the local machine
     * @param timeout   the connection timeout (0==infinite)
     * @return Socket a new socket
     * @throws java.io.IOException          if an I/O error occurs while creating thesocket
     * @throws java.net.UnknownHostException if the IP address of the host cannot be
     *                              determined
     */
    public Socket createSocket(String host, int port, InetAddress localHost,
                               int localPort, int timeout)
        throws IOException {
        return ssl.createSocket(host, port, localHost, localPort, timeout);
    }

    public Socket createSocket(Socket s, String remoteHost, int remotePort,
                               boolean autoClose)
        throws IOException {
        return ssl.createSocket(s, remoteHost, remotePort, autoClose);
    }

}
