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

import org.apache.kerby.config.Conf;
import org.apache.kerby.config.Config;
import org.apache.kerby.event.EventHub;
import org.apache.kerby.kerberos.kerb.common.KrbStreamingDecoder;
import org.apache.kerby.kerberos.kerb.identity.IdentityService;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.identity.backend.MemoryIdentityBackend;
import org.apache.kerby.transport.Network;

import java.io.File;
import java.io.IOException;

public class KdcServer {
    private String kdcHost;
    private int kdcTcpPort;
    private Boolean allowUdp;
    private int kdcUdpPort;
    private String kdcRealm;

    private boolean started;
    private String serviceName;

    private KdcHandler kdcHandler;
    private EventHub eventHub;

    private KdcConfig kdcConfig;
    private Conf backendConfig;

    private IdentityBackend backend;
    private File workDir;
    private File confDir;

    /**
     * Set runtime folder.
     * @param workDir
     */
    public void setWorkDir(File workDir) {
        this.workDir = workDir;
    }

    /**
     * Set conf dir where configuration resources can be loaded. Mainly:
     * kdc.conf, that contains kdc server related items.
     * backend.conf, that contains identity backend related items.
     * @param confDir
     */
    public void setConfDir(File confDir) {
        this.confDir = confDir;
    }

    /**
     * Get configuration folder.
     * @return
     */
    public File getConfDir() {
        return confDir;
    }

    /**
     * Get the backend identity service.
     * @return
     */
    public IdentityService getIdentityService() {
        return backend;
    }

    public void init() {
        try {
            initConfig();
        } catch (IOException e) {
            throw new RuntimeException("Failed to load configurations", e);
        }

        initBackend();
    }

    /**
     * Prepare kdc and backend config, loading kdc.conf and backend.conf.
     * It can be override to add more configuration resources.
     *
     * @throws IOException
     */
    protected void initConfig() throws IOException {
        kdcConfig = new KdcConfig();
        backendConfig = new Conf();

        if (confDir != null && confDir.exists()) {
            File kdcConfFile = new File(confDir, "kdc.conf");
            if (kdcConfFile.exists()) {
                kdcConfig.addIniConfig(kdcConfFile);
            }

            File backendConfFile = new File(confDir, "backend.conf");
            if (backendConfFile.exists()) {
                backendConfig.addIniConfig(backendConfFile);
            }
        }
    }

    private void initBackend() {
        String backendClassName = backendConfig.getString(
                KdcConfigKey.KDC_IDENTITY_BACKEND);
        if (backendClassName == null) {
            backendClassName = MemoryIdentityBackend.class.getCanonicalName();
        }

        Class backendClass = null;
        try {
            backendClass = Class.forName(backendClassName);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("Failed to load backend class: "
                    + backendClassName);
        }

        try {
            backend = (IdentityBackend) backendClass.newInstance();
        } catch (InstantiationException e) {
            throw new RuntimeException("Failed to create backend: "
                    + backendClassName);
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Failed to create backend: "
                    + backendClassName);
        }

        backend.setConfig(backendConfig);
        backend.initialize();
    }

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

    private int getKdcTcpPort() {
        if (kdcTcpPort > 0) {
            return kdcTcpPort;
        }
        return kdcConfig.getKdcTcpPort();
    }

    private boolean allowUdp() {
        if (allowUdp != null) {
            return allowUdp;
        }
        return kdcConfig.allowKdcUdp();
    }

    private int getKdcUdpPort() {
        if (kdcUdpPort > 0) {
            return kdcUdpPort;
        }
        return kdcConfig.getKdcUdpPort();
    }

    public void setKdcHost(String kdcHost) {
        this.kdcHost = kdcHost;
    }

    /**
     * Set to allow UDP or not.
     * @param allowUdp
     */
    public void setAllowUdp(boolean allowUdp) {
        this.allowUdp = allowUdp;
    }

    /**
     * Set KDC tcp port.
     * @param kdcTcpPort
     */
    public void setKdcTcpPort(int kdcTcpPort) {
        this.kdcTcpPort = kdcTcpPort;
    }

    /**
     * Set KDC udp port. Only makes sense when allowUdp is set.
     * @param kdcUdpPort
     */
    public void setKdcUdpPort(int kdcUdpPort) {
        this.kdcUdpPort = kdcUdpPort;
    }

    /**
     * Set KDC realm.
     * @param realm
     */
    public void setKdcRealm(String realm) {
        this.kdcRealm = realm;
    }

    public boolean enableDebug() {
        return kdcConfig.enableDebug();
    }

    protected void doStart() throws Exception {
        backend.start();

        prepareHandler();

        this.eventHub = new EventHub();

        eventHub.register(kdcHandler);

        Network network = new Network();
        network.setStreamingDecoder(new KrbStreamingDecoder());
        eventHub.register(network);

        eventHub.start();
        network.tcpListen(getKdcHost(), getKdcTcpPort());
        if (allowUdp()) {
            network.udpListen(getKdcHost(), getKdcUdpPort());
        }
    }

    private void prepareHandler() {
        this.kdcHandler = new KdcHandler();
        kdcHandler.setConfig(kdcConfig);
        kdcHandler.setIdentityService(backend);
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

        started = false;
    }

    protected void doStop() throws Exception {
        backend.stop();

        eventHub.stop();
    }

    /**
     * Get the KDC config.
     * @return
     */
    protected KdcConfig getKdcConfig() {
        return kdcConfig;
    }

    /**
     * Get backend config.
     * @return
     */
    protected Config getBackendConfig() {
        return backendConfig;
    }

    public boolean isStarted() {
        return started;
    }

    protected void setServiceName(String name) {
        this.serviceName = name;
    }

    protected String getServiceName() {
        if (serviceName != null) {
            return serviceName;
        }
        return kdcConfig.getKdcServiceName();
    }

    protected void setBackend(IdentityBackend backend) {
        this.backend = backend;
    }
}
