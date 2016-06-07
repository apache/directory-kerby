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
package org.apache.kerby.kerberos.kerb.client;

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.EtypeInfo2;
import org.apache.kerby.kerberos.kerb.type.base.EtypeInfo2Entry;
import org.apache.kerby.kerberos.kerb.type.base.KrbError;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.base.MethodData;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public abstract class KrbHandler {

    private static final Logger LOG = LoggerFactory.getLogger(KrbHandler.class);
    private PreauthHandler preauthHandler;

    /**
     * Init with krbcontext.
     *
     * @param context The krbcontext
     */
    public void init(KrbContext context) {
        preauthHandler = new PreauthHandler();
        preauthHandler.init(context);
    }

    /**
     * Handle the kdc request.
     *
     * @param kdcRequest The kdc request
     * @param tryNextKdc try next kdc or not
     * @throws KrbException e
     */
    public void handleRequest(KdcRequest kdcRequest, boolean tryNextKdc) throws KrbException {
        if (!tryNextKdc || kdcRequest.getKdcReq() == null) {
            kdcRequest.process();
        }
        KdcReq kdcReq = kdcRequest.getKdcReq();
        int bodyLen = kdcReq.encodingLength();
        KrbTransport transport = (KrbTransport) kdcRequest.getSessionData();
        boolean isTcp = transport.isTcp();
        ByteBuffer requestMessage;

        if (!isTcp) {
            requestMessage = ByteBuffer.allocate(bodyLen);

        } else {
            requestMessage = ByteBuffer.allocate(bodyLen + 4);
            requestMessage.putInt(bodyLen);
        }
        KrbCodec.encode(kdcReq, requestMessage);
        requestMessage.flip();
        try {
            sendMessage(kdcRequest, requestMessage);
        } catch (IOException e) {
            throw new KrbException("sending message failed", e);
        }
    }

    /**
     * Process the response messabe from kdc.
     *
     * @param kdcRequest The kdc request
     * @param responseMessage The message from kdc
     * @throws KrbException e
     */
    public void onResponseMessage(
            KdcRequest kdcRequest, ByteBuffer responseMessage) throws KrbException {

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
        } else if (messageType == KrbMessageType.KRB_ERROR) {
            KrbError error = (KrbError) kdcRep;
            LOG.info("KDC server response with message: "
                    + error.getErrorCode().getMessage());
            if (error.getErrorCode() == KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED) {
                MethodData methodData = KrbCodec.decode(error.getEdata(), MethodData.class);
                List<PaDataEntry> paDataEntryList = methodData.getElements();
                List<EncryptionType> encryptionTypes = new ArrayList<>();
                for (PaDataEntry paDataEntry : paDataEntryList) {
                    if (paDataEntry.getPaDataType() == PaDataType.ETYPE_INFO2) {
                        EtypeInfo2 etypeInfo2 = KrbCodec.decode(paDataEntry.getPaDataValue(),
                                EtypeInfo2.class);
                        List<EtypeInfo2Entry> info2Entries = etypeInfo2.getElements();
                        for (EtypeInfo2Entry info2Entry : info2Entries) {
                            encryptionTypes.add(info2Entry.getEtype());
                        }
                    }
                }
                kdcRequest.setEncryptionTypes(encryptionTypes);
                kdcRequest.setPreauthRequired(true);
                kdcRequest.resetPrequthContxt();
                handleRequest(kdcRequest, false);
                LOG.info("Retry with the new kdc request including pre-authentication.");
            } else {
                LOG.info(error.getErrorCode().getMessage());
                throw new KrbException(error.getErrorCode(), error.getEtext());
            }
        }
    }

    /**
     * Send message to kdc.
     *
     * @param kdcRequest The kdc request
     * @param requestMessage The request message to kdc
     * @throws IOException e
     */
    protected abstract void sendMessage(KdcRequest kdcRequest,
                                        ByteBuffer requestMessage) throws IOException;
}
