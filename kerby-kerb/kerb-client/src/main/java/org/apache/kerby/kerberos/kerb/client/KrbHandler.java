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

import org.apache.kerby.event.AbstractEventHandler;
import org.apache.kerby.event.Event;
import org.apache.kerby.event.EventType;
import org.apache.kerby.kerberos.kerb.client.event.KrbClientEvent;
import org.apache.kerby.kerberos.kerb.client.event.KrbClientEventType;
import org.apache.kerby.kerberos.kerb.client.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.client.request.AsRequest;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.client.request.TgsRequest;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.common.KrbMessage;
import org.apache.kerby.kerberos.kerb.spec.common.KrbMessageType;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReq;
import org.apache.kerby.transport.Transport;
import org.apache.kerby.transport.event.MessageEvent;
import org.apache.kerby.transport.event.TransportEventType;

import java.nio.ByteBuffer;

public class KrbHandler extends AbstractEventHandler {

    private KrbContext context;
    private PreauthHandler preauthHandler;

    public void init(KrbContext context) {
        this.context = context;
        preauthHandler = new PreauthHandler();
        preauthHandler.init(context);
    }

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] {
                TransportEventType.INBOUND_MESSAGE,
                KrbClientEventType.TGT_INTENT,
                KrbClientEventType.TKT_INTENT
        };
    }

    @Override
    protected void doHandle(Event event) throws Exception {
        EventType eventType = event.getEventType();

        if (eventType == KrbClientEventType.TGT_INTENT ||
                eventType == KrbClientEventType.TKT_INTENT) {
            KdcRequest kdcRequest = (KdcRequest) event.getEventData();
            handleKdcRequest(kdcRequest);
        } else if (event.getEventType() == TransportEventType.INBOUND_MESSAGE) {
            handleMessage((MessageEvent) event);
        }
    }

    protected void handleKdcRequest(KdcRequest kdcRequest) throws KrbException {
        kdcRequest.process();
        KdcReq kdcReq = kdcRequest.getKdcReq();
        Transport transport = kdcRequest.getTransport();
        transport.setAttachment(kdcRequest);
        KrbUtil.sendMessage(kdcReq, transport);
    }

    protected void handleMessage(MessageEvent event) throws Exception {
        ByteBuffer message = event.getMessage();
        KrbMessage kdcRep = KrbUtil.decodeMessage(message);

        KrbMessageType messageType = kdcRep.getMsgType();
        if (messageType == KrbMessageType.AS_REP) {
            KdcRequest kdcRequest = (KdcRequest) event.getTransport().getAttachment();
            kdcRequest.processResponse((KdcRep) kdcRep);
            dispatch(KrbClientEvent.createTgtResultEvent((AsRequest) kdcRequest));
        } else if (messageType == KrbMessageType.TGS_REP) {
            KdcRequest kdcRequest = (KdcRequest) event.getTransport().getAttachment();
            kdcRequest.processResponse((KdcRep) kdcRep);
            dispatch(KrbClientEvent.createTktResultEvent((TgsRequest) kdcRequest));
        }
    }
}
