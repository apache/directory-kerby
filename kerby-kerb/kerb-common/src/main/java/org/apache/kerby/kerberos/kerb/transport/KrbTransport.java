/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.kerberos.kerb.transport;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * Krb transport.
 */
public interface KrbTransport {

    /**
     * Send out a Kerberos message to remote peer.
     * @param message The message to be sent
     * @throws IOException e
     */
    void sendMessage(ByteBuffer message) throws IOException;

    /**
     * Receive a Kerberos message from remote.
     * @return The received message
     * @throws IOException e
     */
    ByteBuffer receiveMessage() throws IOException;

    /**
     * Judge the type of transport, return true if it is tcp,
     * @return false if it is udp.
     */

    boolean isTcp();

    /**
     * Get address from remote side.
     * @return address
     */
    InetAddress getRemoteAddress();

    /**
     * Set an attachment.
     * @param attachment The attachment
     */
    void setAttachment(Object attachment);

    /**
     * Get the attachment set before.
     * @return attachment
     */
    Object getAttachment();

    /**
     * Release and close related resources like connection.
     */
    void release();
}
