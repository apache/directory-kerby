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
package org.apache.kerby.transport.udp;

import org.apache.kerby.event.AbstractEventHandler;
import org.apache.kerby.event.Event;
import org.apache.kerby.event.EventType;
import org.apache.kerby.transport.Connector;
import org.apache.kerby.transport.event.AddressEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;

public class UdpConnector extends Connector {

    public UdpConnector() {
        this(new UdpTransportHandler());
    }

    public UdpConnector(UdpTransportHandler transportHandler) {
        super(transportHandler);

        setEventHandler(new AbstractEventHandler() {
            @Override
            protected void doHandle(Event event) throws Exception {
                if (event.getEventType() == UdpEventType.ADDRESS_CONNECT) {
                    doConnect((AddressEvent) event);
                }
            }

            @Override
            public EventType[] getInterestedEvents() {
                return new EventType[] {
                        UdpEventType.ADDRESS_CONNECT
                };
            }
        });
    }

    @Override
    protected void doConnect(InetSocketAddress sa) {
        AddressEvent event = UdpAddressEvent.createAddressConnectEvent(sa);
        dispatch(event);
    }

    private void doConnect(AddressEvent event) throws IOException {
        InetSocketAddress address = event.getAddress();
        DatagramChannel channel = DatagramChannel.open();
        channel.configureBlocking(false);
        channel.connect(address);

        channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);

        UdpTransport transport = new UdpTransport(channel, address);
        onNewTransport(transport);
    }
}
