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
package org.apache.kerby.kerberos.kerb.admin.server.kpasswd;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * KDC handler to process client requests. Currently only one realm is supported.
 */
public class PasswdServerHandler {
    private static final Logger LOG = LoggerFactory.getLogger(PasswdServerHandler.class);
    private final PasswdServerContext passwdServerContext;

    /**
     * Constructor with passwd context.
     *
     * @param passwdServerContext passwd passwd context
     */
    public PasswdServerHandler(PasswdServerContext passwdServerContext) {
        this.passwdServerContext = passwdServerContext;
        LOG.info("Passwd context realm:" + this.passwdServerContext.getPasswdRealm());
    }

    /**
     * Process the client request message.
     *
     * @throws KrbException e
     * @param receivedMessage The client request message
     * @param remoteAddress Address from remote side
     * @return The response message
     */
    public ByteBuffer handleMessage(ByteBuffer receivedMessage,
                                    InetAddress remoteAddress) throws KrbException {
        System.out.println("Password Server receive message: ");
        System.out.println(new String(receivedMessage.array()));
        String response = "Password server receive message.";
        ByteBuffer responseMessage = ByteBuffer.allocate(response.length() + 4);
        responseMessage.putInt(response.length());
        responseMessage.put(response.getBytes());
        responseMessage.flip();
        return responseMessage;
    }
}
