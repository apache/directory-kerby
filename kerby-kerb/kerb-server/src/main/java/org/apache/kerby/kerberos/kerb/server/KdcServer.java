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
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.IdentityService;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.server.impl.DefaultInternalKdcServerImpl;
import org.apache.kerby.kerberos.kerb.server.impl.InternalKdcServer;

import java.io.File;

/**
 * The implemented Kerberos Server API.
 */
public class KdcServer {
    private final KdcConfig kdcConfig;
    private final BackendConfig backendConfig;
    private final KdcSetting kdcSetting;
    private final KOptions startupOptions;

    private InternalKdcServer innerKdc;

    /**
     * Constructor passing both kdcConfig and backendConfig.
     * @param kdcConfig
     * @param backendConfig
     * @throws KrbException
     */
    public KdcServer(KdcConfig kdcConfig,
                  BackendConfig backendConfig) throws KrbException {
        this.kdcConfig = kdcConfig;
        this.backendConfig = backendConfig;
        startupOptions = new KOptions();
        kdcSetting = new KdcSetting(startupOptions, kdcConfig, backendConfig);
    }

    /**
     * Constructor given confDir where 'kdc.conf' and 'backend.conf' should be
     * available.
     * kdc.conf, that contains kdc server related items.
     * backend.conf, that contains identity backend related items.
     *
     * @param confDir
     * @throws KrbException
     */
    public KdcServer(File confDir) throws KrbException {
        KdcConfig tmpKdcConfig = KdcUtil.getKdcConfig(confDir);
        if (tmpKdcConfig == null) {
            tmpKdcConfig = new KdcConfig();
        }
        this.kdcConfig = tmpKdcConfig;

        BackendConfig tmpBackendConfig = KdcUtil.getBackendConfig(confDir);
        if (tmpBackendConfig == null) {
            tmpBackendConfig = new BackendConfig();
        }
        tmpBackendConfig.setConfDir(confDir);
        this.backendConfig = tmpBackendConfig;

        startupOptions = new KOptions();
        kdcSetting = new KdcSetting(startupOptions, kdcConfig, backendConfig);
    }

    /**
     * Default constructor.
     */
    public KdcServer() {
        kdcConfig = new KdcConfig();
        backendConfig = new BackendConfig();
        startupOptions = new KOptions();
        kdcSetting = new KdcSetting(startupOptions, kdcConfig, backendConfig);
    }

    /**
     * Set KDC realm for ticket request
     * @param realm
     */
    public void setKdcRealm(String realm) {
        startupOptions.add(KdcServerOption.KDC_REALM, realm);
    }

    /**
     * Set KDC host.
     * @param kdcHost
     */
    public void setKdcHost(String kdcHost) {
        startupOptions.add(KdcServerOption.KDC_HOST, kdcHost);
    }

    /**
     * Set KDC port.
     * @param kdcPort
     */
    public void setKdcPort(int kdcPort) {
        startupOptions.add(KdcServerOption.KDC_PORT, kdcPort);
    }

    /**
     * Set KDC tcp port.
     * @param kdcTcpPort
     */
    public void setKdcTcpPort(int kdcTcpPort) {
        startupOptions.add(KdcServerOption.KDC_TCP_PORT, kdcTcpPort);
    }

    /**
     * Set to allow UDP or not.
     * @param allowUdp
     */
    public void setAllowUdp(boolean allowUdp) {
        startupOptions.add(KdcServerOption.ALLOW_UDP, allowUdp);
    }

    /**
     * Set to allow TCP or not.
     * @param allowTcp
     */
    public void setAllowTcp(boolean allowTcp) {
        startupOptions.add(KdcServerOption.ALLOW_TCP, allowTcp);
    }
    /**
     * Set KDC udp port. Only makes sense when allowUdp is set.
     * @param kdcUdpPort
     */
    public void setKdcUdpPort(int kdcUdpPort) {
        startupOptions.add(KdcServerOption.KDC_UDP_PORT, kdcUdpPort);
    }

    /**
     * Set runtime folder.
     * @param workDir
     */
    public void setWorkDir(File workDir) {
        startupOptions.add(KdcServerOption.WORK_DIR, workDir);
    }

    /**
     * Allow to debug so have more logs.
     */
    public void enableDebug() {
        startupOptions.add(KdcServerOption.ENABLE_DEBUG);
    }

    /**
     * Allow to hook customized kdc implementation.
     * @param innerKdcImpl
     */
    public void setInnerKdcImpl(InternalKdcServer innerKdcImpl) {
        startupOptions.add(KdcServerOption.INNER_KDC_IMPL, innerKdcImpl);
    }

    /**
     * Get KDC setting from startup options and configs.
     * @return setting
     */
    public KdcSetting getKdcSetting() {
        return kdcSetting;
    }

    /**
     * Get the KDC config.
     * @return KdcConfig
     */
    public KdcConfig getKdcConfig() {
        return kdcConfig;
    }

    /**
     * Get backend config.
     * @return
     */
    public BackendConfig getBackendConfig() {
        return backendConfig;
    }

    /**
     * Get identity service.
     * @return IdentityService
     */
    public IdentityService getIdentityService() {
        if (innerKdc == null) {
            throw new RuntimeException("Not init yet");
        }
        return innerKdc.getIdentityBackend();
    }

    public void init() throws KrbException {
        if (startupOptions.contains(KdcServerOption.INNER_KDC_IMPL)) {
            innerKdc = (InternalKdcServer) startupOptions.getOptionValue(
                    KdcServerOption.INNER_KDC_IMPL);
        } else {
            innerKdc = new DefaultInternalKdcServerImpl(kdcSetting);
        }

        innerKdc.init();
    }

    public void start() throws KrbException {
        if (innerKdc == null) {
            throw new RuntimeException("Not init yet");
        }
        innerKdc.start();
    }

    public void stop() throws KrbException {
        if (innerKdc != null) {
            innerKdc.stop();
        }
    }
}
