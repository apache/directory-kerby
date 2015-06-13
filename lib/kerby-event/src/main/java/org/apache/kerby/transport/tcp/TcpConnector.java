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
package org.apache.kerby.transport.tcp;

import org.apache.kerby.event.AbstractEventHandler;
import org.apache.kerby.event.Event;
import org.apache.kerby.event.EventType;
import org.apache.kerby.transport.Connector;
import org.apache.kerby.transport.Transport;
import org.apache.kerby.transport.event.AddressEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

public class TcpConnector extends Connector {

    public TcpConnector(StreamingDecoder streamingDecoder) {
        this(new TcpTransportHandler(streamingDecoder));
    }

    public TcpConnector(TcpTransportHandler transportHandler) {
        super(transportHandler);

        setEventHandler(new AbstractEventHandler() {
            @Override
            protected void doHandle(Event event) throws Exception {
                if (event.getEventType() ==  TcpEventType.ADDRESS_CONNECT) {
                    doConnect((AddressEvent) event);
                }
            }

            @Override
            public EventType[] getInterestedEvents() {
                return new EventType[] {
                        TcpEventType.ADDRESS_CONNECT
                };
            }
        });
    }

    @Override
    protected void doConnect(InetSocketAddress sa) {
        AddressEvent event = TcpAddressEvent.createAddressConnectEvent(sa);
        dispatch(event);
    }

    private void doConnect(AddressEvent event) throws IOException {
        SocketChannel channel = SocketChannel.open();
        channel.configureBlocking(false);
        channel.connect(event.getAddress());
        channel.register(selector,
                SelectionKey.OP_CONNECT | SelectionKey.OP_READ | SelectionKey.OP_WRITE);
    }

    @Override
    protected void dealKey(SelectionKey selectionKey) throws IOException {
        if (selectionKey.isConnectable()) {
            doConnect(selectionKey);
        } else {
            super.dealKey(selectionKey);
        }
    }

    private void doConnect(SelectionKey key) throws IOException {
        SocketChannel channel = (SocketChannel) key.channel();
        if (channel.isConnectionPending()) {
            channel.finishConnect();
        }

        Transport transport = new TcpTransport(channel,
                ((TcpTransportHandler) transportHandler).getStreamingDecoder());
        channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE, transport);
        onNewTransport(transport);
    }
}
