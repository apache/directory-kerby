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
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
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
     * @param kdcConfig The kdc config
     * @param backendConfig The backend config
     * @throws KrbException e
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
     * @param confDir The conf dir
     * @throws KrbException e
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
     * @param realm The kdc realm
     */
    public void setKdcRealm(String realm) {
        startupOptions.add(KdcServerOption.KDC_REALM, realm);
    }

    /**
     * Set KDC host.
     * @param kdcHost The kdc host
     */
    public void setKdcHost(String kdcHost) {
        startupOptions.add(KdcServerOption.KDC_HOST, kdcHost);
    }

    /**
     * Set KDC port.
     * @param kdcPort The kdc port
     */
    public void setKdcPort(int kdcPort) {
        startupOptions.add(KdcServerOption.KDC_PORT, kdcPort);
    }

    /**
     * Set KDC tcp port.
     * @param kdcTcpPort The kdc tcp port
     */
    public void setKdcTcpPort(int kdcTcpPort) {
        startupOptions.add(KdcServerOption.KDC_TCP_PORT, kdcTcpPort);
    }

    /**
     * Set to allow UDP or not.
     * @param allowUdp true if allow udp
     */
    public void setAllowUdp(boolean allowUdp) {
        startupOptions.add(KdcServerOption.ALLOW_UDP, allowUdp);
    }

    /**
     * Set to allow TCP or not.
     * @param allowTcp true if allow tcp
     */
    public void setAllowTcp(boolean allowTcp) {
        startupOptions.add(KdcServerOption.ALLOW_TCP, allowTcp);
    }
    /**
     * Set KDC udp port. Only makes sense when allowUdp is set.
     * @param kdcUdpPort The kdc udp port
     */
    public void setKdcUdpPort(int kdcUdpPort) {
        startupOptions.add(KdcServerOption.KDC_UDP_PORT, kdcUdpPort);
    }

    /**
     * Set runtime folder.
     * @param workDir The work dir
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
     *
     * @param innerKdcImpl The inner kdc implementation
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
     *
     * @return backend configuration
     */
    public BackendConfig getBackendConfig() {
        return backendConfig;
    }

    /**
     * Get identity service.
     * @return IdentityService
     */
    public IdentityBackend getIdentityService() {
        if (innerKdc == null) {
            throw new RuntimeException("Not init yet");
        }
        return innerKdc.getIdentityBackend();
    }

    /**
     * Initialize.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     */
    public void init() throws KrbException {
        if (startupOptions.contains(KdcServerOption.INNER_KDC_IMPL)) {
            innerKdc = (InternalKdcServer) startupOptions.getOptionValue(
                    KdcServerOption.INNER_KDC_IMPL);
        } else {
            innerKdc = new DefaultInternalKdcServerImpl(kdcSetting);
        }

        innerKdc.init();
    }

    /**
     * Start the KDC server.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     */
    public void start() throws KrbException {
        if (innerKdc == null) {
            throw new RuntimeException("Not init yet");
        }
        innerKdc.start();
    }

    /**
     * Stop the KDC server.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     */
    public void stop() throws KrbException {
        if (innerKdc != null) {
            innerKdc.stop();
        }
    }
}
