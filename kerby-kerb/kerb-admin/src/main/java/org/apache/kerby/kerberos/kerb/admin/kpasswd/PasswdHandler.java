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
package org.apache.kerby.kerberos.kerb.admin.kpasswd;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kpasswd.request.PasswdRequest;

import java.io.IOException;
import java.nio.ByteBuffer;

public abstract class PasswdHandler {

    /**
     * Init with krbcontext.
     *
     * @param context The krbcontext
     */
    public void init(PasswdContext context) {

    }

    /**
     * Handle the kdc request.
     *
     * @param passwdRequest The kdc request
     * @throws KrbException e
     */
    public void handleRequest(PasswdRequest passwdRequest) throws KrbException {
        passwdRequest.process();
        /*
        ByteBuffer requestMessage;

        requestMessage = ByteBuffer.allocate(bodyLen + 4);
        requestMessage.putInt(bodyLen);

        try {
            sendMessage(passwdRequest, requestMessage);
        } catch (IOException e) {
            throw new KrbException("sending message failed", e);
        }*/
    }

    /**
     * Process the response messabe from kdc.
     *
     * @param passwdRequest The kpasswd request
     * @param responseMessage The message from kdc
     * @throws KrbException e
     */
    public void onResponseMessage(PasswdRequest passwdRequest,
                                  ByteBuffer responseMessage) throws KrbException {
        /*
        KrbMessage kdcRep = null;
        try {
            kdcRep = KrbCodec.decodeMessage(responseMessage);
        } catch (IOException e) {
            throw new KrbException("Krb decoding message failed", e);
        }

        KrbMessageType messageType = kdcRep.getMsgType();
        if (messageType == KrbMessageType.AS_REP) {

            kdcRequest.processResponse((KdcRep) kdcRep);
        } else if (messageType == KrbMessageType.TGS_REP) {
            kdcRequest.processResponse((KdcRep) kdcRep);
        }
        */
    }

    /**
     * Send message to kdc.
     *
     * @param passwdRequest The kdc request
     * @param requestMessage The request message to kdc
     * @throws IOException e
     */
    protected abstract void sendMessage(PasswdRequest passwdRequest,
                                        ByteBuffer requestMessage) throws IOException;
}
