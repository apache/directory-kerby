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
package org.apache.kerby.kerberos.kerb.client.impl.event;

import org.apache.kerby.KOptions;
import org.apache.kerby.event.Event;
import org.apache.kerby.event.EventHub;
import org.apache.kerby.event.EventWaiter;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.impl.AbstractInternalKrbClient;
import org.apache.kerby.kerberos.kerb.client.request.AsRequest;
import org.apache.kerby.kerberos.kerb.client.request.TgsRequest;
import org.apache.kerby.kerberos.kerb.common.KrbStreamingDecoder;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.transport.Network;
import org.apache.kerby.transport.Transport;
import org.apache.kerby.transport.event.TransportEvent;
import org.apache.kerby.transport.event.TransportEventType;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * An event based krb client implementation.
 */
public class EventBasedKrbClient extends AbstractInternalKrbClient {

    private EventKrbHandler krbHandler;
    private EventHub eventHub;
    private EventWaiter eventWaiter;
    private Transport eventTransport;
    private KrbTransport transport;

    @Override
    public void init(KOptions commonOptions) throws KrbException {
        super.init(commonOptions);

        this.krbHandler = new EventKrbHandler();
        krbHandler.init(getContext());

        this.eventHub = new EventHub();
        eventHub.register(krbHandler);

        Network network = new Network();
        network.setStreamingDecoder(new KrbStreamingDecoder());
        eventHub.register(network);

        eventWaiter = eventHub.waitEvent(
                TransportEventType.NEW_TRANSPORT,
                KrbClientEventType.TGT_RESULT,
                KrbClientEventType.TKT_RESULT
        );

        eventHub.start();

        network.tcpConnect(getKdcHost(), getKdcTcpPort());
        if (allowUdp()) {
            network.udpConnect(getKdcHost(), getKdcUdpPort());
        }
        final Event event = eventWaiter.waitEvent(TransportEventType.NEW_TRANSPORT);
        eventTransport = ((TransportEvent) event).getTransport();

        transport = new KrbTransport() {
            @Override
            public void sendMessage(ByteBuffer message) throws IOException {
                eventTransport.sendMessage(message);
            }

            @Override
            public ByteBuffer receiveMessage() throws IOException {
                return null; // NOOP, should not be here, since event based.
            }

            @Override
            public void setAttachment(Object attachment) {
                eventTransport.setAttachment(attachment);
            }

            @Override
            public Object getAttachment() {
                return eventTransport.getAttachment();
            }
        };
    }

    @Override
    protected TgtTicket doRequestTgtTicket(AsRequest tgtTktReq) throws KrbException {
        tgtTktReq.setTransport(transport);

        eventHub.dispatch(KrbClientEvent.createTgtIntentEvent(tgtTktReq));
        Event resultEvent;
        try {
            resultEvent = eventWaiter.waitEvent(KrbClientEventType.TGT_RESULT,
                    getTimeout(), TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new KrbException("Network timeout", e);
        }
        AsRequest asResponse = (AsRequest) resultEvent.getEventData();

        return asResponse.getTicket();
    }

    @Override
    protected ServiceTicket doRequestServiceTicket(TgsRequest ticketReq) throws KrbException {
        ticketReq.setTransport(transport);

        eventHub.dispatch(KrbClientEvent.createTktIntentEvent(ticketReq));
        Event resultEvent;
        try {
            resultEvent = eventWaiter.waitEvent(KrbClientEventType.TKT_RESULT,
                    getTimeout(), TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new KrbException("Network timeout", e);
        }
        TgsRequest tgsResponse = (TgsRequest) resultEvent.getEventData();

        return tgsResponse.getServiceTicket();
    }

}
