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
package org.apache.kerby.kerberos.kerb.client.impl;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbHandler;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;

import java.io.IOException;
import java.nio.ByteBuffer;

public class DefaultKrbHandler extends KrbHandler {

    /**
     * {@inheritDoc}
     */
    @Override
    public void handleRequest(KdcRequest kdcRequest, boolean tryNextKdc) throws KrbException {
        KrbTransport transport = (KrbTransport) kdcRequest.getSessionData();
        transport.setAttachment(kdcRequest);

        super.handleRequest(kdcRequest, tryNextKdc);
        ByteBuffer receivedMessage = null;
        try {
            receivedMessage = transport.receiveMessage();
        } catch (IOException e) {
            throw new KrbException("Receiving response message failed", e);
        }
        super.onResponseMessage(kdcRequest, receivedMessage);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void sendMessage(KdcRequest kdcRequest,
                               ByteBuffer requestMessage) throws IOException {
        KrbTransport transport = (KrbTransport) kdcRequest.getSessionData();
        transport.sendMessage(requestMessage);
    }
}
