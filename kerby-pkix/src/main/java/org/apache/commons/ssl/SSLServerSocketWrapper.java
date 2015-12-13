/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/SSLServerSocketWrapper.java $
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

package org.apache.commons.ssl;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.ServerSocketChannel;

/**
 * Wraps an SSLServerSocket - NOTE that the accept() method applies a number of
 * important common-ssl settings before returning the SSLSocket!
 *
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 20-Nov-2006
 */
public class SSLServerSocketWrapper extends SSLServerSocket {
    protected SSLServerSocket s;
    protected SSL ssl;
    protected SSLWrapperFactory wf;

    public SSLServerSocketWrapper(SSLServerSocket s, SSL ssl,
                                  SSLWrapperFactory wf)
        throws IOException {
        super();
        this.s = s;
        this.ssl = ssl;
        this.wf = wf;
    }

    /* javax.net.ssl.SSLServerSocket */

    public Socket accept() throws IOException {
        SSLSocket secureSocket = (SSLSocket) s.accept();

        // Do the commons-ssl usual housekeeping for every socket:
        ssl.doPreConnectSocketStuff(secureSocket);
        InetAddress addr = secureSocket.getInetAddress();
        String hostName = addr.getHostName();
        ssl.doPostConnectSocketStuff(secureSocket, hostName);

        return wf.wrap(secureSocket);
    }

    public String[] getEnabledCipherSuites() {
        return s.getEnabledCipherSuites();
    }

    public String[] getEnabledProtocols() {
        return s.getEnabledProtocols();
    }

    public boolean getEnableSessionCreation() {
        return s.getEnableSessionCreation();
    }

    public boolean getNeedClientAuth() {
        return s.getNeedClientAuth();
    }

    public String[] getSupportedCipherSuites() {
        return s.getSupportedCipherSuites();
    }

    public String[] getSupportedProtocols() {
        return s.getSupportedProtocols();
    }

    public boolean getUseClientMode() {
        return s.getUseClientMode();
    }

    public boolean getWantClientAuth() {
        return s.getWantClientAuth();
    }

    public void setEnabledCipherSuites(String[] suites) {
        s.setEnabledCipherSuites(suites);
    }

    public void setEnabledProtocols(String[] protocols) {
        s.setEnabledProtocols(protocols);
    }

    public void setEnableSessionCreation(boolean flag) {
        s.setEnableSessionCreation(flag);
    }

    public void setNeedClientAuth(boolean need) {
        s.setNeedClientAuth(need);
    }

    public void setUseClientMode(boolean use) {
        s.setUseClientMode(use);
    }

    public void setWantClientAuth(boolean want) {
        s.setWantClientAuth(want);
    }

    /* java.net.Socket */

    public void bind(SocketAddress endpoint) throws IOException {
        s.bind(endpoint);
    }

    public void bind(SocketAddress ep, int bl) throws IOException {
        s.bind(ep, bl);
    }

    public void close() throws IOException {
        s.close();
    }

    public ServerSocketChannel getChannel() {
        return s.getChannel();
    }

    public InetAddress getInetAddress() {
        return s.getInetAddress();
    }

    public int getLocalPort() {
        return s.getLocalPort();
    }

    public SocketAddress getLocalSocketAddress() {
        return s.getLocalSocketAddress();
    }

    public int getReceiveBufferSize() throws SocketException {
        return s.getReceiveBufferSize();
    }

    public boolean getReuseAddress() throws SocketException {
        return s.getReuseAddress();
    }

    public int getSoTimeout() throws IOException {
        return s.getSoTimeout();
    }

    public boolean isBound() {
        return s.isBound();
    }

    public boolean isClosed() {
        return s.isClosed();
    }

    public void setReceiveBufferSize(int size) throws SocketException {
        s.setReceiveBufferSize(size);
    }

    public void setReuseAddress(boolean on) throws SocketException {
        s.setReuseAddress(on);
    }

    public void setSoTimeout(int timeout) throws SocketException {
        s.setSoTimeout(timeout);
    }

    public String toString() {
        return s.toString();
    }

    /*  Java 1.5
     public void setPerformancePreferences(int connectionTime, int latency, int bandwidth)
     {
         s.setPerformancePreferences( connectionTime, latency, bandwidth );
     }
     */


}
