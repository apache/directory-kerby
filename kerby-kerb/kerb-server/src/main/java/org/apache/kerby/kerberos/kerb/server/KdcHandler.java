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
package org.apache.kerby.kerberos.kerb.server;

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.server.request.AsRequest;
import org.apache.kerby.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.server.request.TgsRequest;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.KrbError;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.type.kdc.TgsReq;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * KDC handler to process client requests. Currently only one realm is supported.
 */
public class KdcHandler {
    private static final Logger LOG = LoggerFactory.getLogger(KdcHandler.class);
    private final KdcContext kdcContext;

    /**
     * Constructor with kdc context.
     *
     * @param kdcContext kdc context
     */
    public KdcHandler(KdcContext kdcContext) {
        this.kdcContext = kdcContext;
    }

    /**
     * Process the client request message.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     * @param receivedMessage The client request message
     * @param  isTcp whether the protocol is tcp
     * @param remoteAddress Address from remote side
     * @return The response message
     */
    public ByteBuffer handleMessage(ByteBuffer receivedMessage, boolean isTcp,
                                    InetAddress remoteAddress) throws KrbException {
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
                throw new KrbException(KrbErrorCode.WRONG_REALM,
                    "Invalid realm from kdc request: " + realm);
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
                KrbError krbError = new KrbError();
                krbError.setStime(KerberosTime.now());
                krbError.setSusec(100);
                if (e.getKrbErrorCode() != null) {
                    krbError.setErrorCode(e.getKrbErrorCode());
                } else {
                    krbError.setErrorCode(KrbErrorCode.UNKNOWN_ERR);
                }
                krbError.setCrealm(kdcContext.getKdcRealm());
                if (kdcRequest.getClientPrincipal() != null) {
                    krbError.setCname(kdcRequest.getClientPrincipal());
                }
                krbError.setRealm(kdcContext.getKdcRealm());
                if (kdcRequest.getServerPrincipal() != null) {
                    krbError.setSname(kdcRequest.getServerPrincipal());
                } else {
                    PrincipalName serverPrincipal = kdcRequest.getKdcReq().getReqBody().getSname();
                    serverPrincipal.setRealm(kdcRequest.getKdcReq().getReqBody().getRealm());
                    krbError.setSname(serverPrincipal);
                }
                if (e.getKrbErrorCode().equals(KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY)) {
                    krbError.setEtext("PREAUTH_FAILED");
                } else {
                    krbError.setEtext(e.getMessage());
                }
                krbResponse = krbError;
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
    }

    /**
     * Process the recoverable exception.
     *
     * @param e The exception return by kdc
     * @param kdcRequest kdc request
     * @return The KrbError
     */
    private KrbMessage handleRecoverableException(KdcRecoverableException e,
                                                  KdcRequest kdcRequest)
            throws KrbException {
        LOG.info("KRB error occurred while processing request:"
                + e.getMessage());

        KrbError error = e.getKrbError();
        error.setStime(KerberosTime.now());
        error.setSusec(100);
        error.setErrorCode(e.getKrbError().getErrorCode());
        error.setRealm(kdcContext.getKdcRealm());
        if (kdcRequest != null) {
            error.setSname(kdcRequest.getKdcReq().getReqBody().getCname());
        } else {
            error.setSname(new PrincipalName("NONE"));
        }
        error.setEtext(e.getMessage());
        return error;
    }

    /**
     * Get request realm.
     * @param kdcReq kdc request
     * @return realm
     */
    private String getRequestRealm(KdcReq kdcReq) {
        String realm = kdcReq.getReqBody().getRealm();
        if (realm == null && kdcReq.getReqBody().getCname() != null) {
            realm = kdcReq.getReqBody().getCname().getRealm();
        }

        return realm;
    }
}
