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

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.identity.IdentityService;
import org.apache.kerby.kerberos.kerb.server.impl.InternalKdcServer;
import org.apache.kerby.kerberos.kerb.server.impl.InternalKdcServerImpl;
import org.apache.kerby.kerberos.kerb.server.impl.event.EventBasedKdcServer;

import java.io.File;

public class KdcServer {
    private KOptions commonOptions;
    private InternalKdcServer innerKdc;

    /**
     * Default constructor.
     */
    public KdcServer() {
        commonOptions = new KOptions();
    }

    /**
     * Set KDC config.
     * @param kdcConfig
     */
    public void setKdcConfig(KdcConfig kdcConfig) {
        commonOptions.add(KdcServerOption.KDC_CONFIG, kdcConfig);
    }

    /**
     * Set backend config.
     * @param backendConfig
     */
    public void setBackendConfig(BackendConfig backendConfig) {
        commonOptions.add(KdcServerOption.BACKEND_CONFIG, backendConfig);
    }

    /**
     * Set conf dir where configuration resources can be loaded. Mainly:
     * kdc.conf, that contains kdc server related items.
     * backend.conf, that contains identity backend related items.
     *
     * Note confDir is only used when KDC and backend config aren't set.
     *
     * @param confDir
     */
    public void setConfDir(File confDir) {
        commonOptions.add(KdcServerOption.CONF_DIR, confDir);
    }

    /**
     * Set KDC realm for ticket request
     * @param realm
     */
    public void setKdcRealm(String realm) {
        commonOptions.add(KdcServerOption.KDC_REALM, realm);
    }

    /**
     * Set KDC host.
     * @param kdcHost
     */
    public void setKdcHost(String kdcHost) {
        commonOptions.add(KdcServerOption.KDC_HOST, kdcHost);
    }

    /**
     * Set KDC tcp port.
     * @param kdcTcpPort
     */
    public void setKdcTcpPort(int kdcTcpPort) {
        commonOptions.add(KdcServerOption.KDC_TCP_PORT, kdcTcpPort);
    }

    /**
     * Set to allow UDP or not.
     * @param allowUdp
     */
    public void setAllowUdp(boolean allowUdp) {
        commonOptions.add(KdcServerOption.ALLOW_UDP, allowUdp);
    }

    /**
     * Set KDC udp port. Only makes sense when allowUdp is set.
     * @param kdcUdpPort
     */
    public void setKdcUdpPort(int kdcUdpPort) {
        commonOptions.add(KdcServerOption.KDC_UDP_PORT, kdcUdpPort);
    }

    /**
     * Use event model. By default blocking model is used.
     */
    public void useEventModel() {
        commonOptions.add(KdcServerOption.USE_EVENT_MODEL);
    }

    /**
     * Set runtime folder.
     * @param workDir
     */
    public void setWorkDir(File workDir) {
        commonOptions.add(KdcServerOption.WORK_DIR, workDir);
    }

    public void enableDebug() {
        commonOptions.add(KdcServerOption.ENABLE_DEBUG);
    }

    /**
     * Get KDC setting from startup options and configs.
     * Note it must be called after init().
     * @return setting
     */
    public KdcSetting getSetting() {
        if (innerKdc == null) {
            throw new RuntimeException("Not init yet");
        }
        return innerKdc.getSetting();
    }

    /**
     * Get identity service.
     * @return IdentityService
     */
    public IdentityService getIdentityService() {
        if (innerKdc == null) {
            throw new RuntimeException("Not init yet");
        }
        return innerKdc.getIdentityService();
    }

    /**
     * Init the KDC server.
     */
    public void init() {
        if (commonOptions.contains(KdcServerOption.USE_EVENT_MODEL)) {
            innerKdc = new EventBasedKdcServer();
        } else {
            innerKdc = new InternalKdcServerImpl();
        }
        innerKdc.init(commonOptions);
    }

    public void start() {
        innerKdc.start();
    }

    public void stop() {
        innerKdc.stop();
    }
}
