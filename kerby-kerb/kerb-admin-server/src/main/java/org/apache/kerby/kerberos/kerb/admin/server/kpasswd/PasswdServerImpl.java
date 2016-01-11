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
package org.apache.kerby.kerberos.kerb.admin.server.kpasswd;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcServerOption;
import org.apache.kerby.kerberos.kerb.server.KdcSetting;
import org.apache.kerby.kerberos.kerb.server.KdcUtil;
import org.apache.kerby.kerberos.kerb.server.impl.DefaultInternalKdcServerImpl;
import org.apache.kerby.kerberos.kerb.server.impl.InternalKdcServer;

import java.io.File;

/**
 * The implemented Kerberos Server API.
 */
public class PasswdServerImpl {
    private final KdcConfig passwdConfig;
    private final BackendConfig backendConfig;
    private final KdcSetting passwdSetting;
    private final KOptions startupOptions;

    private InternalKdcServer innerKdc;

    /**
     * Constructor passing both passwdConfig and backendConfig.
     * @param passwdConfig The passwd config
     * @param backendConfig The backend config
     * @throws KrbException e
     */
    public PasswdServerImpl(KdcConfig passwdConfig,
                           BackendConfig backendConfig) throws KrbException {
        this.passwdConfig = passwdConfig;
        this.backendConfig = backendConfig;
        startupOptions = new KOptions();
        passwdSetting = new KdcSetting(startupOptions, passwdConfig, backendConfig);
    }

    /**
     * Constructor given confDir where 'passwd.conf' and 'backend.conf' should be
     * available.
     * passwd.conf, that contains passwd passwd related items.
     * backend.conf, that contains identity backend related items.
     *
     * @param confDir The conf dir
     * @throws KrbException e
     */
    public PasswdServerImpl(File confDir) throws KrbException {
        KdcConfig tmpKdcConfig = KdcUtil.getKdcConfig(confDir);
        if (tmpKdcConfig == null) {
            tmpKdcConfig = new KdcConfig();
        }
        this.passwdConfig = tmpKdcConfig;

        BackendConfig tmpBackendConfig = KdcUtil.getBackendConfig(confDir);
        if (tmpBackendConfig == null) {
            tmpBackendConfig = new BackendConfig();
        }
        tmpBackendConfig.setConfDir(confDir);
        this.backendConfig = tmpBackendConfig;

        startupOptions = new KOptions();
        passwdSetting = new KdcSetting(startupOptions, passwdConfig, backendConfig);
    }

    /**
     * Default constructor.
     */
    public PasswdServerImpl() {
        passwdConfig = new KdcConfig();
        backendConfig = new BackendConfig();
        startupOptions = new KOptions();
        passwdSetting = new KdcSetting(startupOptions, passwdConfig, backendConfig);
    }

    /**
     * Set KDC realm for ticket request
     * @param realm The passwd realm
     */
    public void setKdcRealm(String realm) {
        startupOptions.add(KdcServerOption.KDC_REALM, realm);
    }

    /**
     * Set KDC host.
     * @param passwdHost The passwd host
     */
    public void setKdcHost(String passwdHost) {
        startupOptions.add(KdcServerOption.KDC_HOST, passwdHost);
    }

    /**
     * Set KDC port.
     * @param passwdPort The passwd port
     */
    public void setKdcPort(int passwdPort) {
        startupOptions.add(KdcServerOption.KDC_PORT, passwdPort);
    }

    /**
     * Set KDC tcp port.
     * @param passwdTcpPort The passwd tcp port
     */
    public void setKdcTcpPort(int passwdTcpPort) {
        startupOptions.add(KdcServerOption.KDC_TCP_PORT, passwdTcpPort);
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
     * @param passwdUdpPort The passwd udp port
     */
    public void setKdcUdpPort(int passwdUdpPort) {
        startupOptions.add(KdcServerOption.KDC_UDP_PORT, passwdUdpPort);
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
     * Allow to hook customized passwd implementation.
     *
     * @param innerKdcImpl The inner passwd implementation
     */
    public void setInnerKdcImpl(InternalKdcServer innerKdcImpl) {
        startupOptions.add(KdcServerOption.INNER_KDC_IMPL, innerKdcImpl);
    }

    /**
     * Get KDC setting from startup options and configs.
     * @return setting
     */
    public KdcSetting getKdcSetting() {
        return passwdSetting;
    }

    /**
     * Get the KDC config.
     * @return PasswdServerConfig
     */
    public KdcConfig getKdcConfig() {
        return passwdConfig;
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
     * @throws KrbException e.
     */
    public void init() throws KrbException {
        if (startupOptions.contains(KdcServerOption.INNER_KDC_IMPL)) {
            innerKdc = (InternalKdcServer) startupOptions.getOptionValue(
                    KdcServerOption.INNER_KDC_IMPL);
        } else {
            innerKdc = new DefaultInternalKdcServerImpl(passwdSetting);
        }

        innerKdc.init();
    }

    /**
     * Start the KDC passwd.
     *
     * @throws KrbException e.
     */
    public void start() throws KrbException {
        if (innerKdc == null) {
            throw new RuntimeException("Not init yet");
        }
        innerKdc.start();
    }

    /**
     * Stop the KDC passwd.
     *
     * @throws KrbException e.
     */
    public void stop() throws KrbException {
        if (innerKdc != null) {
            innerKdc.stop();
        }
    }
}
