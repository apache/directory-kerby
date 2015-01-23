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
package org.apache.kerby.event.udp;

import junit.framework.Assert;
import org.apache.kerby.event.EventHandler;
import org.apache.kerby.event.EventHub;
import org.apache.kerby.transport.Acceptor;
import org.apache.kerby.transport.MessageHandler;
import org.apache.kerby.transport.event.MessageEvent;
import org.apache.kerby.transport.event.TransportEventType;
import org.apache.kerby.transport.udp.UdpAcceptor;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

public class TestUdpServer extends TestUdpBase {

    private EventHub eventHub;

    @Before
    public void setUp() throws IOException {
        setUpServer();
    }

    private void setUpServer() throws IOException {
        eventHub = new EventHub();

        EventHandler messageHandler = new MessageHandler() {
            @Override
            protected void handleMessage(MessageEvent msgEvent) {
                if (msgEvent.getEventType() == TransportEventType.INBOUND_MESSAGE) {
                    msgEvent.getTransport().sendMessage(msgEvent.getMessage());
                }
            }
        };
        eventHub.register(messageHandler);

        Acceptor acceptor = new UdpAcceptor();
        eventHub.register(acceptor);

        eventHub.start();
        acceptor.listen(serverHost, serverPort);
    }

    @Test
    public void testUdpTransport() throws IOException, InterruptedException {
        Thread.sleep(10);

        DatagramChannel socketChannel = DatagramChannel.open();
        socketChannel.configureBlocking(true);
        SocketAddress sa = new InetSocketAddress(serverHost, serverPort);
        socketChannel.send(ByteBuffer.wrap(TEST_MESSAGE.getBytes()), sa);
        ByteBuffer byteBuffer = ByteBuffer.allocate(65536);
        socketChannel.receive(byteBuffer);
        byteBuffer.flip();
        clientRecvedMessage = recvBuffer2String(byteBuffer);

        Assert.assertEquals(TEST_MESSAGE, clientRecvedMessage);
    }

    @After
    public void cleanup() {
        eventHub.stop();
    }
}
