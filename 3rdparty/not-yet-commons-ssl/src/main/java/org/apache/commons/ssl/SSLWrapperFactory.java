/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/SSLWrapperFactory.java $
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

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.Socket;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 19-Sep-2006
 */
public interface SSLWrapperFactory {

    /**
     * Wraps an SSLSSocket.
     *
     * @param s SSLSocket to wrap.
     * @return The new wrapped SSLSocket.
     * @throws java.io.IOException if wrapping failed
     */
    public Socket wrap(Socket s) throws IOException;

    /**
     * Wraps an SSLServerSocket.
     *
     * @param s   The SSLServerSocket to wrap.
     * @param ssl The SSL object that created the SSLServerSocket.
     *            This way some important commons-ssl config can be applied
     *            to the returned socket.
     * @return The new wrapped SSLServerSocket.
     * @throws java.io.IOException if wrapping failed
     */
    public SSLServerSocket wrap(SSLServerSocket s, SSL ssl)
        throws IOException;


    /**
     * NO_WRAP doesn't wrap the SSLSocket.  It does wrap the SSLServerSocket
     * so that we can do the usual housekeeping after accept() that we like to
     * do on every socket.  E.g. setSoTimeout, setEnabledProtocols,
     * setEnabledCiphers, setUseClientMode, and the hostname verifier (which
     * should be very rare on SSLServerSockets!).
     */
    public final static SSLWrapperFactory NO_WRAP = new SSLWrapperFactory() {
        // Notice!  No wrapping!
        public Socket wrap(Socket s) { return s; }

        // We still wrap the ServerSocket, but we don't wrap the result of the
        // the accept() call.
        public SSLServerSocket wrap(SSLServerSocket s, SSL ssl)
            throws IOException {
            return new SSLServerSocketWrapper(s, ssl, this);
        }
    };

    /**
     * DUMB_WRAP is useful to make sure that wrapping the sockets doesn't break
     * anything.  It doesn't actually do anything interesting in its wrapped
     * implementations.
     */
    public final static SSLWrapperFactory DUMB_WRAP = new SSLWrapperFactory() {
        public Socket wrap(Socket s) { return new SSLSocketWrapper(s); }

        public SSLServerSocket wrap(SSLServerSocket s, SSL ssl)
            throws IOException {
            return new SSLServerSocketWrapper(s, ssl, this);
        }
    };


}
