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
package org.apache.kerby.kerberos.kerb.admin.kpasswd.impl;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.request.PasswdRequest;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.PasswdHandler;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;

import java.io.IOException;
import java.nio.ByteBuffer;

public class DefaultPasswdHandler extends PasswdHandler {

    /**
     * Client handle request.
     * Use super.handleRequest to send message,
     * and use this.handleRequest to receive message.
     */
    @Override
    public void handleRequest(PasswdRequest passwdRequest) throws KrbException {
        /** super is used to send messsage*/
        super.handleRequest(passwdRequest);

        KrbTransport transport = passwdRequest.getTransport();
        ByteBuffer receiveMessage = null;
        try {
            receiveMessage = transport.receiveMessage();
        } catch (IOException e) {
            throw new KrbException("Client receives response message failed.");
        }
        super.onResponseMessage(passwdRequest, receiveMessage);
    }

    /**
     * Override super's sendMessage method.
     */
    @Override
    protected void sendMessage(PasswdRequest passwdRequest,
                               ByteBuffer requestMessage) throws IOException {
        KrbTransport transport = passwdRequest.getTransport();
        transport.sendMessage(requestMessage);
    }
}
