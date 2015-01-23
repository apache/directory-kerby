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
import org.apache.kerby.transport.Acceptor;
import org.apache.kerby.transport.Transport;
import org.apache.kerby.transport.event.AddressEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

public class TcpAcceptor extends Acceptor {

    public TcpAcceptor(StreamingDecoder streamingDecoder) {
        this(new TcpTransportHandler(streamingDecoder));
    }

    public TcpAcceptor(TcpTransportHandler transportHandler) {
        super(transportHandler);

        setEventHandler(new AbstractEventHandler() {
            @Override
            protected void doHandle(Event event) throws Exception {
                if (event.getEventType() == TcpEventType.ADDRESS_BIND) {
                    try {
                        doBind((AddressEvent) event);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            }

            @Override
            public EventType[] getInterestedEvents() {
                return new EventType[] {
                        TcpEventType.ADDRESS_BIND
                };
            }
        });
    }

    @Override
    protected void doListen(InetSocketAddress socketAddress) {
        AddressEvent event = TcpAddressEvent.createAddressBindEvent(socketAddress);
        dispatch(event);
    }

    @Override
    protected void dealKey(SelectionKey selectionKey) throws IOException {
        if (selectionKey.isAcceptable()) {
            doAccept(selectionKey);
        } else {
            super.dealKey(selectionKey);
        }
    }

    void doAccept(SelectionKey key) throws IOException {
        ServerSocketChannel server = (ServerSocketChannel) key.channel();
        SocketChannel channel;

        try {
            while ((channel = server.accept()) != null) {
                channel.configureBlocking(false);
                channel.socket().setTcpNoDelay(true);
                channel.socket().setKeepAlive(true);

                Transport transport = new TcpTransport(channel,
                    ((TcpTransportHandler) transportHandler).getStreamingDecoder());

                channel.register(selector,
                    SelectionKey.OP_READ | SelectionKey.OP_WRITE, transport);
                onNewTransport(transport);
            }
        } catch (ClosedByInterruptException e) {
            // No op as normal
        }
    }

    protected void doBind(AddressEvent event) throws IOException {
        ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.configureBlocking(false);
        ServerSocket serverSocket = serverSocketChannel.socket();
        serverSocket.bind(event.getAddress());
        serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT, serverSocketChannel);
    }

}
