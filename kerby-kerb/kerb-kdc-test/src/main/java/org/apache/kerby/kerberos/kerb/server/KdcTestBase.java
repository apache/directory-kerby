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

import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.net.ServerSocket;

public abstract class KdcTestBase {
    protected static final String TEST_PASSWORD = "123456";

    protected String kdcRealm;
    protected String clientPrincipal;
    protected String serverPrincipal;

    protected String hostname = "localhost";
    protected int tcpPort = -1;
    protected int udpPort = -1;

    protected TestKdcServer kdcServer;
    protected KrbClient krbClnt;

    protected boolean allowUdp() {
        return true;
    }

    @Before
    public void setUp() throws Exception {
        tcpPort = getServerPort();

        if (allowUdp()) {
            udpPort = getServerPort();
        }

        setUpKdcServer();

        setUpClient();
        createPrincipals();
    }

    /**
     * Prepare KrbClient startup options and config.
     * @throws Exception
     */
    protected void prepareKrbClient() throws Exception {
        if (useEventModelClient()) {
            krbClnt.useEventModel();
        }
    }

    /**
     * Prepare KDC startup options and config.
     * @throws Exception
     */
    protected void prepareKdcServer() throws Exception {
        kdcServer.setKdcHost(hostname);
        if (tcpPort > 0) {
            kdcServer.setKdcTcpPort(tcpPort);
        }

        kdcServer.setAllowUdp(allowUdp());
        if (udpPort > 0) {
            kdcServer.setKdcUdpPort(udpPort);
        }

        if (useEventModelKdc()) {
            kdcServer.useEventModel();
        }
    }

    protected boolean useEventModelKdc() {
        return false;
    }

    protected boolean useEventModelClient() {
        return false;
    }

    protected void setUpKdcServer() throws Exception {
        kdcServer = new TestKdcServer();
        prepareKdcServer();
        kdcServer.init();

        kdcRealm = kdcServer.getKdcRealm();
        clientPrincipal = "drankye@" + kdcRealm;
        serverPrincipal = "test-service/localhost@" + kdcRealm;
    }

    protected void setUpClient() throws Exception {
        krbClnt = new KrbClient();
        prepareKrbClient();

        krbClnt.setKdcHost(hostname);
        if (tcpPort > 0) {
            krbClnt.setKdcTcpPort(tcpPort);
        }
        krbClnt.setAllowUdp(allowUdp());
        if (udpPort > 0) {
            krbClnt.setKdcUdpPort(udpPort);
        }

        krbClnt.setTimeout(5);
        krbClnt.setKdcRealm(kdcServer.getKdcRealm());
    }

    protected void createPrincipals() {
        kdcServer.createKrbtgtPrincipal();
        kdcServer.createPrincipals(serverPrincipal);
    }

    /**
     * Get a server socket point for testing usage, either TCP or UDP.
     * @return server socket point
     */
    private static int getServerPort() {
        int serverPort = 0;

        try {
            ServerSocket serverSocket = new ServerSocket(0);
            serverPort = serverSocket.getLocalPort();
            serverSocket.close();
        } catch (IOException e) {
            throw new RuntimeException("Failed to get a server socket point");
        }

        return serverPort;
    }

    @After
    public void tearDown() throws Exception {
        kdcServer.stop();
    }
}