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
package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.impl;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminHandler;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.request.AdminRequest;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;

import java.io.IOException;
import java.nio.ByteBuffer;

public class DefaultAdminHandler extends AdminHandler {

    /**
     * Use super.handleRequest to send message
     * and use this to receive message.
     */
    @Override
    public void handleRequest(AdminRequest adminRequest) throws KrbException {
        /**super is used to send message*/
        super.handleRequest(adminRequest);

        KrbTransport transport = adminRequest.getTransport();
        ByteBuffer receiveMessage = null;
        try {
            receiveMessage = transport.receiveMessage();
        } catch (IOException e) {
            throw new KrbException("Admin receives response message failed", e);
        }
        super.onResponseMessage(adminRequest, receiveMessage);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void sendMessage(AdminRequest adminRequest,
                               ByteBuffer requestMessage) throws IOException {
        KrbTransport transport = adminRequest.getTransport();
        transport.sendMessage(requestMessage);
    }
}
