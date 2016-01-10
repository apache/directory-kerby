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
package org.apache.kerby.kerberos.kerb.admin.server;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * KDC handler to process client requests. Currently only one realm is supported.
 */
public class AdminServerHandler {
    private static final Logger LOG = LoggerFactory.getLogger(AdminServerHandler.class);
    private final AdminServerContext adminServerContext;

    /**
     * Constructor with kdc context.
     *
     * @param adminServerContext admin server context
     */
    public AdminServerHandler(AdminServerContext adminServerContext) {
        this.adminServerContext = adminServerContext;
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
        return null;
        /*
        KrbMessage krbRequest;
        KdcRequest kdcRequest = null;
        KrbMessage krbResponse;

        ByteBuffer message = receivedMessage.duplicate();

        try {
            krbRequest = KrbCodec.decodeMessage(receivedMessage);
        } catch (IOException e) {
            LOG.error("Krb decoding message failed", e);
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_MSG_TYPE, "Krb decoding message failed");
        }

        KrbMessageType messageType = krbRequest.getMsgType();
        if (messageType == KrbMessageType.TGS_REQ || messageType
                == KrbMessageType.AS_REQ) {
            KdcReq kdcReq = (KdcReq) krbRequest;
            String realm = getRequestRealm(kdcReq);
            if (realm == null || !kdcContext.getKdcRealm().equals(realm)) {
                LOG.error("Invalid realm from kdc request: " + realm);
                throw new KrbException("Invalid realm from kdc request: " + realm);
            }

            if (messageType == KrbMessageType.TGS_REQ) {
                kdcRequest = new TgsRequest((TgsReq) kdcReq, kdcContext);
            } else if (messageType == KrbMessageType.AS_REQ) {
                kdcRequest = new AsRequest((AsReq) kdcReq, kdcContext);
            } else {
                LOG.error("Invalid message type: " + messageType);
                throw new KrbException(KrbErrorCode.KRB_AP_ERR_MSG_TYPE);
            }
        }

        // For checksum
        if (kdcRequest == null) {
            throw new KrbException("Kdc request is null.");
        }
        kdcRequest.setReqPackage(message);
        if (remoteAddress == null) {
            throw new KrbException("Remote address is null, not available.");
        }
        kdcRequest.setClientAddress(remoteAddress);
        kdcRequest.isTcp(isTcp);

        try {
            kdcRequest.process();
            krbResponse = kdcRequest.getReply();
        } catch (KrbException e) {
            if (e instanceof KdcRecoverableException) {
                krbResponse = handleRecoverableException(
                        (KdcRecoverableException) e, kdcRequest);
            } else {
                throw e;
            }
        }

        int bodyLen = krbResponse.encodingLength();
        ByteBuffer responseMessage;
        if (isTcp) {
            responseMessage = ByteBuffer.allocate(bodyLen + 4);
            responseMessage.putInt(bodyLen);
        } else {
            responseMessage = ByteBuffer.allocate(bodyLen);
        }
        KrbCodec.encode(krbResponse, responseMessage);
        responseMessage.flip();

        return responseMessage;
        */
    }
}
