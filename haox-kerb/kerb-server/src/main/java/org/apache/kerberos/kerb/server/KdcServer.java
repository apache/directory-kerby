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
package org.apache.kerberos.kerb.server;

import org.apache.haox.event.EventHub;
import org.apache.kerberos.kerb.common.KrbStreamingDecoder;
import org.apache.kerberos.kerb.identity.IdentityService;
import org.apache.haox.transport.Acceptor;
import org.apache.haox.transport.tcp.TcpAcceptor;

import java.io.File;

public class KdcServer {
    private String kdcHost;
    private short kdcPort;
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

    private short getKdcPort() {
        if (kdcPort > 0) {
            return kdcPort;
        }
        return kdcConfig.getKdcPort();
    }

    public void setKdcHost(String kdcHost) {
        this.kdcHost = kdcHost;
    }

    public void setKdcPort(short kdcPort) {
        this.kdcPort = kdcPort;
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

        Acceptor acceptor = new TcpAcceptor(new KrbStreamingDecoder());
        eventHub.register(acceptor);

        eventHub.start();
        acceptor.listen(getKdcHost(), getKdcPort());
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

    public KdcConfig getConfig() {
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
