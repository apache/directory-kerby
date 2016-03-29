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
package org.apache.kerby.kerberos.kerb.admin.kadmin.remote;

import org.apache.kerby.kerberos.kerb.admin.tool.KadminCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.request.AdminRequest;
import org.apache.kerby.kerberos.kerb.admin.tool.AdminReq;
import org.apache.kerby.kerberos.kerb.admin.tool.AdminMessage;
import org.apache.kerby.kerberos.kerb.admin.tool.AdminMessageType;
import org.apache.kerby.xdr.type.XdrString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;

public abstract class AdminHandler {

    private static final Logger LOG = LoggerFactory.getLogger(AdminHandler.class);

    /**
     * Init with krbcontext.
     *
     * @param context The krbcontext
     */
    public void init(AdminContext context) {

    }

    /**
     * Handle the kdc request.
     *
     * @param adminRequest The admin request
     * @throws KrbException e
     */
    public void handleRequest(AdminRequest adminRequest) throws KrbException {
        adminRequest.process();
        AdminReq adminReq = adminRequest.getAdminReq();
        //ByteBuffer requestMessage = adminReq.getMessageBuffer();
        ByteBuffer requestMessage = KadminCode.encodeMessage(adminReq);
        requestMessage.flip();

        try {
            sendMessage(adminRequest, requestMessage);
        } catch (IOException e) {
            throw new KrbException("Admin sends request message failed", e);
        }

    }

    /**
     * Process the response message from kdc.
     *
     * @param adminRequest The admin request
     * @param responseMessage The message from kdc
     * @throws KrbException e
     */
    public void onResponseMessage(AdminRequest adminRequest,
                                  ByteBuffer responseMessage) throws KrbException {
        //AdminMessage replyMessage = null;
        try {
            XdrString decoded = new XdrString();
            decoded.decode(responseMessage);
            String reply = decoded.getValue();
            System.out.println(reply);
            //replyMessage = KadminCode.decodeMessage(responseMessage);
        } catch (IOException e) {
            throw new KrbException("Kadmin decoding message failed", e);
        }
        /*AdminMessageType messageType = replyMessage.getAdminMessageType();
        if (messageType == AdminMessageType.AD_REP &&
                adminRequest.getAdminReq().getAdminMessageType() == AdminMessageType.AD_REQ) {
            String receiveMsg = new String(replyMessage.getMessageBuffer().array());
            System.out.println("Admin receive message success: " + receiveMsg);
        } else {
            throw new RuntimeException("Receive wrong reply");
        }*/
    }

    /**
     * Send message to kdc.
     *
     * @param adminRequest The admin request
     * @param requestMessage The request message to kdc
     * @throws IOException e
     */
    protected abstract void sendMessage(AdminRequest adminRequest,
                                        ByteBuffer requestMessage) throws IOException;
}
