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

import org.apache.kerby.util.NetworkUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.SocketChannel;

public class KdcServerTest {
    private String serverHost = "localhost";
    private int serverPort = -1;

    private KdcServer kdcServer;

    @BeforeEach
    public void setUp() throws Exception {
        kdcServer = new KdcServer();
        kdcServer.setKdcHost(serverHost);
        kdcServer.setAllowUdp(false);
        kdcServer.setAllowTcp(true);
        serverPort = NetworkUtil.getServerPort();
        kdcServer.setKdcTcpPort(serverPort);
        kdcServer.init();
        kdcServer.start();
    }

    @Test
    public void testKdc() throws IOException, InterruptedException {
        Thread.sleep(15);

        try (SocketChannel socketChannel = SocketChannel.open()) {
            socketChannel.configureBlocking(true);
            SocketAddress sa = new InetSocketAddress(serverHost, serverPort);
            socketChannel.connect(sa);

            Assertions.assertTrue(socketChannel.isConnected());
        }
    }

    @AfterEach
    public void tearDown() throws Exception {
        kdcServer.stop();
    }
}