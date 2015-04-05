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
package org.apache.kerby.kerberos.kerb.server.impl.event;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.request.AsRequest;
import org.apache.kerby.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.server.request.TgsRequest;
import org.apache.kerby.kerberos.kerb.spec.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.spec.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.spec.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.spec.kdc.TgsReq;
import org.apache.kerby.transport.MessageHandler;
import org.apache.kerby.transport.Transport;
import org.apache.kerby.transport.event.MessageEvent;
import org.apache.kerby.transport.tcp.TcpTransport;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

/**
 * KDC handler to process client requests. Currently only one realm is supported.
 */
public class EventKdcHandler extends MessageHandler {

    private final KdcContext kdcContext;

    public EventKdcHandler(KdcContext kdcContext) {
        this.kdcContext = kdcContext;
    }

    @Override
    protected void handleMessage(MessageEvent event) throws Exception {
        ByteBuffer message = event.getMessage();
        Transport transport = event.getTransport();

        KrbMessage krbRequest = KrbUtil.decodeMessageOld(message);
        KdcRequest kdcRequest = null;

        KrbMessageType messageType = krbRequest.getMsgType();
        if (messageType == KrbMessageType.TGS_REQ || messageType
                == KrbMessageType.AS_REQ) {
            KdcReq kdcReq = (KdcReq) krbRequest;
            String realm = getRequestRealm(kdcReq);
            if (realm == null || ! kdcContext.getKdcRealm().equals(realm)) {
                throw new KrbException("Invalid realm from kdc request: " + realm);
            }

            if (messageType == KrbMessageType.TGS_REQ) {
                kdcRequest = new TgsRequest((TgsReq) kdcReq, kdcContext);
            } else if (messageType == KrbMessageType.AS_REQ) {
                kdcRequest = new AsRequest((AsReq) kdcReq, kdcContext);
            }
        }

        InetSocketAddress clientAddress = transport.getRemoteAddress();
        kdcRequest.setClientAddress(clientAddress.getAddress());
        boolean isTcp = (transport instanceof TcpTransport);
        kdcRequest.isTcp(isTcp);

        try {
            kdcRequest.process();

            KrbMessage krbResponse = kdcRequest.getReply();
            KrbUtil.sendMessageOld(krbResponse, transport);
        } catch (Exception e) {
            //TODO: log the error
            System.out.println("Error occured while processing request:"
                    + e.getMessage());
        }
    }

    private String getRequestRealm(KdcReq kdcReq) {
        String realm = kdcReq.getReqBody().getRealm();
        if (realm == null && kdcReq.getReqBody().getCname() != null) {
            realm = kdcReq.getReqBody().getCname().getRealm();
        }

        return realm;
    }
}
