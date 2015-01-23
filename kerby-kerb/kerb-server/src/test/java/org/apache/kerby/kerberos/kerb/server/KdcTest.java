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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public class KdcTest {

    private String serverHost = "localhost";
    private short serverPort = 8089;

    private SimpleKdcServer kdcServer;

    @Before
    public void setUp() throws Exception {
        kdcServer = new SimpleKdcServer();
        kdcServer.setKdcHost(serverHost);
        kdcServer.setKdcTcpPort(serverPort);
        kdcServer.init();
        kdcServer.start();
    }

    @Test
    public void testKdc() throws IOException, InterruptedException {
        Thread.sleep(15);

        SocketChannel socketChannel = SocketChannel.open();
        socketChannel.configureBlocking(true);
        SocketAddress sa = new InetSocketAddress(serverHost, serverPort);
        socketChannel.connect(sa);

        String BAD_KRB_MESSAGE = "Hello World!";
        ByteBuffer writeBuffer = ByteBuffer.allocate(4 + BAD_KRB_MESSAGE.getBytes().length);
        writeBuffer.putInt(BAD_KRB_MESSAGE.getBytes().length);
        writeBuffer.put(BAD_KRB_MESSAGE.getBytes());
        writeBuffer.flip();

        socketChannel.write(writeBuffer);
    }

    @After
    public void tearDown() throws Exception {
        kdcServer.stop();
    }
}