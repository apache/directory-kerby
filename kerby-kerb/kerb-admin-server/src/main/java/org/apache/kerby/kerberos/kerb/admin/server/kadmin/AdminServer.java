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
package org.apache.kerby.kerberos.kerb.admin.server.kadmin;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.impl.DefaultInternalAdminServerImpl;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.impl.InternalAdminServer;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;

import java.io.File;

/**
 * The implemented Kerberos admin admin API.
 * We add the KdcConfig as a member variable to AdminServer,
 * In order to make it easy to use LocalKadminImpl.
 * The Kdc Config of corresponding KDC can be read from ConfDir.
 */
public class AdminServer {
    private final AdminServerConfig adminServerConfig;
    private final BackendConfig backendConfig;
    private final KdcConfig kdcConfig;
    private final AdminServerSetting adminServerSetting;
    private final KOptions startupOptions;

    private InternalAdminServer innerAdminServer;

    /**
     * Constructor passing adminServerConfig, kdcConfig and backendConfig.
     * @param adminServerConfig The admin server config
     * @param backendConfig The backend config
     * @param kdcConfig The kdc config
     * @throws KrbException e
     */
    public AdminServer(AdminServerConfig adminServerConfig,
                     BackendConfig backendConfig, KdcConfig kdcConfig) throws KrbException {
        this.adminServerConfig = adminServerConfig;
        this.kdcConfig = kdcConfig;
        this.backendConfig = backendConfig;
        startupOptions = new KOptions();
        adminServerSetting = new AdminServerSetting(startupOptions,
            adminServerConfig, kdcConfig, backendConfig);
    }

    /**
     * Constructor given confDir where 'adminServer.conf', 'kdc.conf' and
     * 'backend.conf' should be available.
     * adminServer.conf that contains adminServer related items.
     * kdc.conf, that contains kdc related items.
     * backend.conf, that contains identity backend related items.
     *
     * @param confDir The conf dir
     * @throws KrbException e
     */
    public AdminServer(File confDir) throws KrbException {
        AdminServerConfig tmpAdminServerConfig =
            AdminServerUtil.getAdminServerConfig(confDir);
        if (tmpAdminServerConfig == null) {
            tmpAdminServerConfig = new AdminServerConfig();
        }
        this.adminServerConfig = tmpAdminServerConfig;

        KdcConfig tmpKdcConfig = AdminServerUtil.getKdcConfig(confDir);
        if (tmpKdcConfig == null) {
            tmpKdcConfig = new KdcConfig();
        }
        this.kdcConfig = tmpKdcConfig;

        BackendConfig tmpBackendConfig = AdminServerUtil.getBackendConfig(confDir);
        if (tmpBackendConfig == null) {
            tmpBackendConfig = new BackendConfig();
        }
        tmpBackendConfig.setConfDir(confDir);
        this.backendConfig = tmpBackendConfig;

        startupOptions = new KOptions();
        adminServerSetting = new AdminServerSetting(startupOptions,
            adminServerConfig, kdcConfig, backendConfig);
    }

    /**
     * Default constructor.
     */
    public AdminServer() {
        adminServerConfig = new AdminServerConfig();
        backendConfig = new BackendConfig();
        kdcConfig = new KdcConfig();
        startupOptions = new KOptions();
        adminServerSetting = new AdminServerSetting(startupOptions,
            adminServerConfig, kdcConfig, backendConfig);
    }

    /**
     * Set Admin realm for ticket request
     * @param realm The kdc realm
     */
    public void setAdminServerRealm(String realm) {
        startupOptions.add(AdminServerOption.ADMIN_REALM, realm);
    }

    /**
     * Set Admin host.
     * @param kdcHost The kdc host
     */
    public void setAdminHost(String kdcHost) {
        startupOptions.add(AdminServerOption.ADMIN_HOST, kdcHost);
    }

    /**
     * Set Admin port.
     * @param kdcPort The kdc port
     */
    public void setAdminServerPort(int kdcPort) {
        startupOptions.add(AdminServerOption.ADMIN_PORT, kdcPort);
    }

    /**
     * Set Admin tcp port.
     * @param kdcTcpPort The kdc tcp port
     */
    public void setAdminTcpPort(int kdcTcpPort) {
        startupOptions.add(AdminServerOption.ADMIN_TCP_PORT, kdcTcpPort);
    }

    /**
     * Set to allow UDP or not.
     * @param allowUdp true if allow udp
     */
    public void setAllowUdp(boolean allowUdp) {
        startupOptions.add(AdminServerOption.ALLOW_UDP, allowUdp);
    }

    /**
     * Set to allow TCP or not.
     * @param allowTcp true if allow tcp
     */
    public void setAllowTcp(boolean allowTcp) {
        startupOptions.add(AdminServerOption.ALLOW_TCP, allowTcp);
    }
    /**
     * Set Admin udp port. Only makes sense when allowUdp is set.
     * @param kdcUdpPort The kdc udp port
     */
    public void setAdminUdpPort(int kdcUdpPort) {
        startupOptions.add(AdminServerOption.ADMIN_UDP_PORT, kdcUdpPort);
    }

    /**
     * Set runtime folder.
     * @param workDir The work dir
     */
    public void setWorkDir(File workDir) {
        startupOptions.add(AdminServerOption.WORK_DIR, workDir);
    }

    /**
     * Allow to debug so have more logs.
     */
    public void enableDebug() {
        startupOptions.add(AdminServerOption.ENABLE_DEBUG);
    }

    /**
     * Allow to hook customized kdc implementation.
     *
     * @param innerAdminServerImpl The inner kdc implementation
     */
    public void setInnerAdminServerImpl(InternalAdminServer innerAdminServerImpl) {
        startupOptions.add(AdminServerOption.INNER_ADMIN_IMPL, innerAdminServerImpl);
    }

    /**
     * Get Admin setting from startup options and configs.
     * @return setting
     */
    public AdminServerSetting getAdminServerSetting() {
        return adminServerSetting;
    }

    /**
     * Get the Admin config.
     * @return AdminServerConfig
     */
    public AdminServerConfig getAdminServerConfig() {
        return adminServerConfig;
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
        if (innerAdminServer == null) {
            throw new RuntimeException("Not init yet");
        }
        return innerAdminServer.getIdentityBackend();
    }

    /**
     * Initialize.
     *
     * @throws KrbException e.
     */
    public void init() throws KrbException {
        if (startupOptions.contains(AdminServerOption.INNER_ADMIN_IMPL)) {
            innerAdminServer = (InternalAdminServer) startupOptions.getOptionValue(
                AdminServerOption.INNER_ADMIN_IMPL);
        } else {
            innerAdminServer =
                new DefaultInternalAdminServerImpl(adminServerSetting);
        }

        innerAdminServer.init();
    }

    /**
     * Start the Admin admin.
     *
     * @throws KrbException e.
     */
    public void start() throws KrbException {
        if (innerAdminServer == null) {
            throw new RuntimeException("Not init yet");
        }
        innerAdminServer.start();
    }

    /**
     * Stop the Admin admin.
     *
     * @throws KrbException e.
     */
    public void stop() throws KrbException {
        if (innerAdminServer != null) {
            innerAdminServer.stop();
        }
    }
}
