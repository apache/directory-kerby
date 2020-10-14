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
import org.apache.kerby.kerberos.kerb.request.KrbIdentity;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.xnio.sasl.SaslWrapper;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

public class DefaultAdminHandler extends AdminHandler {

    /**
     * Use super.handleRequest to send message
     * and use this to receive message.
     */
    @Override
    public void handleRequest(AdminRequest adminRequest, SaslWrapper sasl) throws KrbException {
        // super is used to send message
        super.handleRequest(adminRequest, sasl);

        KrbTransport transport = adminRequest.getTransport();
        try {
            ByteBuffer receiveMessage = transport.receiveMessage();
            ByteBuffer unwrapMessage = ByteBuffer.wrap(sasl.unwrap(receiveMessage));
            super.onResponseMessage(adminRequest, unwrapMessage);
        } catch (IOException e) {
            throw new KrbException("Admin receives response message failed", e);
        }
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

    @Override
    public List<String> handleRequestForList(AdminRequest adminRequest,
                                             SaslWrapper sasl) throws KrbException {
        // send message
        super.handleRequest(adminRequest, sasl);

        KrbTransport transport = adminRequest.getTransport();
        List<String> prinicalList;
        try {
            ByteBuffer receiveMessage = transport.receiveMessage();
            ByteBuffer unwrapMessage = ByteBuffer.wrap(sasl.unwrap(receiveMessage));
            prinicalList = super.onResponseMessageForList(adminRequest, unwrapMessage);
        } catch (IOException e) {
            throw new KrbException("Admin receives response message failed", e);
        }

        return prinicalList;
    }

    @Override
    protected byte[] handleRequestForBytes(AdminRequest adminRequest,
                                           SaslWrapper sasl) throws KrbException {
        super.handleRequest(adminRequest, sasl);
        
        KrbTransport transport = adminRequest.getTransport();
        byte[] keytabFileBytes;
        try {
            ByteBuffer receiveMessage = transport.receiveMessage();
            ByteBuffer unwrapMessage = ByteBuffer.wrap(sasl.unwrap(receiveMessage));
            keytabFileBytes = super.onResponseMessageForBytesArray(adminRequest, unwrapMessage);
        } catch (IOException e) {
            throw new KrbException("Admin receives response message failed", e);
        }
        return keytabFileBytes;
    }

    @Override
    protected KrbIdentity handleRequestForIdentity(AdminRequest adminRequest,
                                                   SaslWrapper sasl) throws KrbException {
        super.handleRequest(adminRequest, sasl);

        KrbTransport transport = adminRequest.getTransport();
        KrbIdentity identity;
        try {
            ByteBuffer receiveMessage = transport.receiveMessage();
            ByteBuffer unwrapMessage = ByteBuffer.wrap(sasl.unwrap(receiveMessage));
            identity = super.onResponseMessageForIdentity(adminRequest, unwrapMessage);
        } catch (IOException e) {
            throw new KrbException("Admin receives response message failed", e);
        }
        return identity;
    }
}
