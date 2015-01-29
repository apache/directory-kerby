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

import org.apache.kerby.event.EventHub;
import org.apache.kerby.kerberos.kerb.common.KrbStreamingDecoder;
import org.apache.kerby.kerberos.kerb.identity.IdentityService;
import org.apache.kerby.transport.Network;

import java.io.File;

public class KdcServer {
    private String kdcHost;
    private short kdcTcpPort;
    private short kdcUdpPort;
    private String kdcRealm;

    private boolean started;
    private String serviceName = "HaoxKdc";

    private KdcHandler kdcHandler;
    private EventHub eventHub;

    protected KdcConfig kdcConfig;
    protected IdentityService identityService;
    protected File workDir;

    public KdcServer() {
        kdcConfig = new KdcConfig();
    }

    public void init() {
        initConfig();

        initWorkDir();
    }

    protected void initWorkDir() {
        String path = kdcConfig.getWorkDir();
        File file;
        if (path != null) {
            file = new File(path);
            file.mkdirs();
        } else {
            file = new File(".");
        }

        this.workDir = file;
    }

    protected void initConfig() {}

    public void start() {
        try {
            doStart();
        } catch (Exception e) {
            throw new RuntimeException("Failed to start " + getServiceName(), e);
        }

        started = true;
    }

    private static KdcServer server;

    public static void main(String[] args) {
        if (args.length == 0) {
            //FIXME host and config should be loaded from configuration.
            String serverHost = "localhost";
            short serverPort = 8087;

            server = new KdcServer();
            server.setKdcHost(serverHost);
            server.setKdcTcpPort(serverPort);
            server.init();
            server.start();
            System.out.println("KDC Server started.");
        } else if (args[0].equals("stop")){
            System.out.println("server is null? " + (server == null));
//            server.stop();//FIXME can't get the server instance here
            System.out.println("KDC Server stoped.");
        }
    }

    public String getKdcRealm() {
        if (kdcRealm != null) {
            return kdcRealm;
        }
        return kdcConfig.getKdcRealm();
    }

    private String getKdcHost() {
        if (kdcHost != null) {
            return kdcHost;
        }
        return kdcConfig.getKdcHost();
    }

    private short getKdcTcpPort() {
        if (kdcTcpPort > 0) {
            return kdcTcpPort;
        }
        return kdcConfig.getKdcTcpPort();
    }

    private short getKdcUdpPort() {
        if (kdcUdpPort > 0) {
            return kdcUdpPort;
        }
        return kdcConfig.getKdcUdpPort();
    }

    public void setKdcHost(String kdcHost) {
        this.kdcHost = kdcHost;
    }

    public void setKdcTcpPort(short kdcTcpPort) {
        this.kdcTcpPort = kdcTcpPort;
    }

    public void setKdcUdpPort(short kdcUdpPort) {
        this.kdcUdpPort = kdcUdpPort;
    }

    public void setKdcRealm(String realm) {
        this.kdcRealm = realm;
    }

    public boolean enableDebug() {
        return kdcConfig.enableDebug();
    }

    protected void doStart() throws Exception {
        prepareHandler();

        this.eventHub = new EventHub();

        eventHub.register(kdcHandler);

        Network network = new Network();
        network.setStreamingDecoder(new KrbStreamingDecoder());
        eventHub.register(network);

        eventHub.start();
        network.tcpListen(getKdcHost(), getKdcTcpPort());
        network.udpListen(getKdcHost(), getKdcUdpPort());
    }

    private void prepareHandler() {
        this.kdcHandler = new KdcHandler();
        kdcHandler.setConfig(kdcConfig);
        kdcHandler.setIdentityService(identityService);
        if (kdcRealm != null) {
            kdcHandler.setKdcRealm(kdcRealm);
        }
        kdcHandler.init();
    }

    public void stop() {
        try {
            doStop();
        } catch (Exception e) {
            throw new RuntimeException("Failed to stop " + getServiceName());
        }
    }

    protected void doStop() throws Exception {
        eventHub.stop();
    }

    public KdcConfig getKdcConfig() {
        return kdcConfig;
    }

    public boolean isStarted() {
        return started;
    }

    protected void setStarted( boolean started ) {
        this.started = started;
    }

    protected void setServiceName( String name ) {
        this.serviceName = name;
    }

    protected String getServiceName() {
        if (serviceName != null) {
            return serviceName;
        }
        return kdcConfig.getKdcServiceName();
    }

    public IdentityService getIdentityService() {
        return identityService;
    }

    protected void setIdentityService(IdentityService identityService) {
        this.identityService = identityService;
    }
}
