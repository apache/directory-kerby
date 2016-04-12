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
import org.apache.kerby.kerberos.kerb.admin.server.kpasswd.impl.DefaultInternalPasswdServerImpl;
import org.apache.kerby.kerberos.kerb.admin.server.kpasswd.impl.InternalPasswdServer;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;

import java.io.File;

/**
 * The implemented Kerberos passwd passwd API.
 */
public class PasswdServer {
    private final PasswdServerConfig passwdServerConfig;
    private final BackendConfig backendConfig;
    private final PasswdServerSetting passwdServerSetting;
    private final KOptions startupOptions;

    private InternalPasswdServer innerPasswdServer;

    /**
     * Constructor passing both passwdConfig and backendConfig.
     * @param passwdConfig The passwd config
     * @param backendConfig The backend config
     * @throws KrbException e
     */
    public PasswdServer(PasswdServerConfig passwdConfig,
                        BackendConfig backendConfig) throws KrbException {
        this.passwdServerConfig = passwdConfig;
        this.backendConfig = backendConfig;
        startupOptions = new KOptions();
        passwdServerSetting = new PasswdServerSetting(startupOptions,
            passwdConfig, backendConfig);
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
    public PasswdServer(File confDir) throws KrbException {
        PasswdServerConfig tmpPasswdServerConfig =
            PasswdServerUtil.getPasswdServerConfig(confDir);
        if (tmpPasswdServerConfig == null) {
            tmpPasswdServerConfig = new PasswdServerConfig();
        }
        this.passwdServerConfig = tmpPasswdServerConfig;

        BackendConfig tmpBackendConfig = PasswdServerUtil.getBackendConfig(confDir);
        if (tmpBackendConfig == null) {
            tmpBackendConfig = new BackendConfig();
        }
        tmpBackendConfig.setConfDir(confDir);
        this.backendConfig = tmpBackendConfig;

        startupOptions = new KOptions();
        passwdServerSetting = new PasswdServerSetting(startupOptions,
            passwdServerConfig, backendConfig);
    }

    /**
     * Default constructor.
     */
    public PasswdServer() {
        passwdServerConfig = new PasswdServerConfig();
        backendConfig = new BackendConfig();
        startupOptions = new KOptions();
        passwdServerSetting = new PasswdServerSetting(startupOptions,
            passwdServerConfig, backendConfig);
    }

    /**
     * Set Passwd realm for ticket request
     * @param realm The passwd realm
     */
    public void setPasswdServerRealm(String realm) {
        startupOptions.add(PasswdServerOption.ADMIN_REALM, realm);
    }

    /**
     * Set Passwd host.
     * @param passwdHost The passwd host
     */
    public void setPasswdHost(String passwdHost) {
        startupOptions.add(
                PasswdServerOption.ADMIN_HOST,
                passwdHost);
    }

    /**
     * Set Passwd port.
     * @param passwdPort The passwd port
     */
    public void setPasswdServerPort(int passwdPort) {
        startupOptions.add(
                PasswdServerOption.ADMIN_PORT,
                passwdPort);
    }

    /**
     * Set Passwd tcp port.
     * @param passwdTcpPort The passwd tcp port
     */
    public void setPasswdTcpPort(int passwdTcpPort) {
        startupOptions.add(
                PasswdServerOption.ADMIN_TCP_PORT,
                passwdTcpPort);
    }

    /**
     * Set to allow UDP or not.
     * @param allowUdp true if allow udp
     */
    public void setAllowUdp(boolean allowUdp) {
        startupOptions.add(
                PasswdServerOption.ALLOW_UDP,
                allowUdp);
    }

    /**
     * Set to allow TCP or not.
     * @param allowTcp true if allow tcp
     */
    public void setAllowTcp(boolean allowTcp) {
        startupOptions.add(
                PasswdServerOption.ALLOW_TCP,
                allowTcp);
    }
    /**
     * Set Passwd udp port. Only makes sense when allowUdp is set.
     * @param passwdUdpPort The passwd udp port
     */
    public void setPasswdUdpPort(int passwdUdpPort) {
        startupOptions.add(
                PasswdServerOption.ADMIN_UDP_PORT,
                passwdUdpPort);
    }

    /**
     * Set runtime folder.
     * @param workDir The work dir
     */
    public void setWorkDir(File workDir) {
        startupOptions.add(
                PasswdServerOption.WORK_DIR,
                workDir);
    }

    /**
     * Allow to debug so have more logs.
     */
    public void enableDebug() {
        startupOptions.add(
                PasswdServerOption.ENABLE_DEBUG);
    }

    /**
     * Allow to hook customized passwd implementation.
     *
     * @param innerPasswdServerImpl The inner passwd implementation
     */
    public void setInnerPasswdServerImpl(InternalPasswdServer innerPasswdServerImpl) {
        startupOptions.add(
                PasswdServerOption.INNER_ADMIN_IMPL,
                innerPasswdServerImpl);
    }

    /**
     * Get Passwd setting from startup options and configs.
     * @return setting
     */
    public PasswdServerSetting getPasswdServerSetting() {
        return passwdServerSetting;
    }

    /**
     * Get the Passwd config.
     * @return PasswdServerConfig
     */
    public PasswdServerConfig getPasswdServerConfig() {
        return passwdServerConfig;
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
        if (innerPasswdServer == null) {
            throw new RuntimeException("Not init yet");
        }
        return innerPasswdServer.getIdentityBackend();
    }

    /**
     * Initialize.
     *
     * @throws KrbException e.
     */
    public void init() throws KrbException {
        if (startupOptions.contains(PasswdServerOption.INNER_ADMIN_IMPL)) {
            innerPasswdServer = (InternalPasswdServer) startupOptions.getOptionValue(
                PasswdServerOption.INNER_ADMIN_IMPL);
        } else {
            innerPasswdServer =
                new DefaultInternalPasswdServerImpl(passwdServerSetting);
        }

        innerPasswdServer.init();
    }

    /**
     * Start the Passwd passwd.
     *
     * @throws KrbException e.
     */
    public void start() throws KrbException {
        if (innerPasswdServer == null) {
            throw new RuntimeException("Not init yet");
        }
        innerPasswdServer.start();
    }

    /**
     * Stop the Passwd passwd.
     *
     * @throws KrbException e.
     */
    public void stop() throws KrbException {
        if (innerPasswdServer != null) {
            innerPasswdServer.stop();
        }
    }
}
