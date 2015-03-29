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
package org.apache.kerby.kerberos.kerb.client.impl.blocking;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.spec.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.spec.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;

import java.io.IOException;
import java.nio.ByteBuffer;

public class BlockingKrbHandler {

    private PreauthHandler preauthHandler;

    public void init(KrbContext context) {
        preauthHandler = new PreauthHandler();
        preauthHandler.init(context);
    }

    public void handleRequest(KdcRequest kdcRequest) throws KrbException {
        kdcRequest.process();
        KdcReq kdcReq = kdcRequest.getKdcReq();
        KrbTransport transport = kdcRequest.getTransport();
        transport.setAttachment(kdcRequest);
        KrbMessage kdcRep = null;

        try {
            KrbUtil.sendMessage(kdcReq, transport);

            ByteBuffer message = transport.receiveMessage();
            if (message != null) {
                kdcRep = KrbUtil.decodeMessage(message);
            } else {
                throw new KrbException("No valid response recved");
            }
        } catch (IOException e) {
            throw new KrbException("Transport or decoding error occurred", e);
        }

        KrbMessageType messageType = kdcRep.getMsgType();
        if (messageType == KrbMessageType.AS_REP) {
            kdcRequest.processResponse((KdcRep) kdcRep);
        } else if (messageType == KrbMessageType.TGS_REP) {
            kdcRequest.processResponse((KdcRep) kdcRep);
        }
    }
}
