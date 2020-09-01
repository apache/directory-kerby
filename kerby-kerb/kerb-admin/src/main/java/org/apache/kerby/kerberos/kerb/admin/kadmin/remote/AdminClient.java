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
package org.apache.kerby.kerberos.kerb.admin.kadmin.remote;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.Kadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.impl.DefaultInternalAdminClient;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.impl.InternalAdminClient;

import java.io.File;
import java.util.List;

/**
 * A Admin client API for applications to interact with Admin Server
 */
public class AdminClient {

    private final AdminConfig adminConfig;
    private final KOptions commonOptions;
    private final AdminSetting adminSetting;

    private InternalAdminClient innerClient;

    /**
     * Default constructor.
     * @throws KrbException e
     */
    public AdminClient() throws KrbException {
        this.adminConfig = AdminUtil.getDefaultConfig();
        this.commonOptions = new KOptions();
        this.adminSetting = new AdminSetting(commonOptions, adminConfig);
    }

    /**
     * Construct with prepared AdminConfig.
     * @param adminConfig The krb config
     */
    public AdminClient(AdminConfig adminConfig) {
        this.adminConfig = adminConfig;
        this.commonOptions = new KOptions();
        this.adminSetting = new AdminSetting(commonOptions, adminConfig);
    }

    /**
     * Constructor with conf dir
     * @param confDir The conf dir
     * @throws KrbException e
     */
    public AdminClient(File confDir) throws KrbException {
        this.commonOptions = new KOptions();
        this.adminConfig = AdminUtil.getConfig(confDir);
        this.adminSetting = new AdminSetting(commonOptions, adminConfig);
    }

    /**
     * Constructor with prepared AdminClient.
     * @param krbClient The krb client
     */
    public AdminClient(AdminClient krbClient) {
        this.commonOptions = krbClient.commonOptions;
        this.adminConfig = krbClient.adminConfig;
        this.adminSetting = krbClient.adminSetting;
        this.innerClient = krbClient.innerClient;
    }

    /**
     * Set KDC realm for ticket request
     * @param realm The realm
     */
    public void setAdminRealm(String realm) {
        commonOptions.add(AdminOption.ADMIN_REALM, realm);
    }

    public void setKeyTabFile(File file) {
        commonOptions.add(AdminOption.KEYTAB_FILE, file);
    }

    /**
     * Set Admin Server host.
     * @param kdcHost The kdc host
     */
    public void setKdcHost(String kdcHost) {
        commonOptions.add(AdminOption.ADMIN_HOST, kdcHost);
    }

    /**
     * Set Admin Server tcp port.
     * @param kdcTcpPort The kdc tcp port
     */
    public void setAdminTcpPort(int kdcTcpPort) {
        if (kdcTcpPort < 1) {
            throw new IllegalArgumentException("Invalid port");
        }
        commonOptions.add(AdminOption.ADMIN_TCP_PORT, kdcTcpPort);
        setAllowTcp(true);
    }

    /**
     * Set to allow UDP or not.
     * @param allowUdp true if allow udp
     */
    public void setAllowUdp(boolean allowUdp) {
        commonOptions.add(AdminOption.ALLOW_UDP, allowUdp);
    }

    /**
     * Set to allow TCP or not.
     * @param allowTcp true if allow tcp
     */
    public void setAllowTcp(boolean allowTcp) {
        commonOptions.add(AdminOption.ALLOW_TCP, allowTcp);
    }

    /**
     * Set Admin Server udp port. Only makes sense when allowUdp is set.
     * @param adminUdpPort The kdc udp port
     */
    public void setAdminUdpPort(int adminUdpPort) {
        if (adminUdpPort < 1) {
            throw new IllegalArgumentException("Invalid port");
        }
        commonOptions.add(AdminOption.ADMIN_UDP_PORT, adminUdpPort);
        setAllowUdp(true);
    }

    /**
     * Set time out for connection
     * @param timeout in seconds
     */
    public void setTimeout(int timeout) {
        commonOptions.add(AdminOption.CONN_TIMEOUT, timeout);
    }

    /**
     * Init the client.
     * @throws KrbException e
     */
    public void init() throws KrbException {
        innerClient = new DefaultInternalAdminClient(adminSetting);
        innerClient.init();
    }

    /**
     * Get krb client settings from options and configs.
     * @return setting
     */
    public AdminSetting getSetting() {
        return adminSetting;
    }

    public AdminConfig getAdminConfig() {
        return adminConfig;
    }

    public void requestAddPrincipal(String principal) throws KrbException {
        Kadmin remote = new RemoteKadminImpl(innerClient);
        remote.addPrincipal(principal);
    }

    public void requestAddPrincipal(String principal, String password) throws KrbException {
        Kadmin remote = new RemoteKadminImpl(innerClient);
        remote.addPrincipal(principal, password);
    }

    public void requestDeletePrincipal(String principal) throws KrbException {
        Kadmin remote = new RemoteKadminImpl(innerClient);
        remote.deletePrincipal(principal);
    }

    public void requestRenamePrincipal(String oldPrincipal, String newPrincipal) throws KrbException {
        Kadmin remote = new RemoteKadminImpl(innerClient);
        remote.renamePrincipal(oldPrincipal, newPrincipal);
    }

    public List<String> requestGetprincs() throws KrbException {
        Kadmin remote = new RemoteKadminImpl(innerClient);
        List<String> principalLists = remote.getPrincipals();
        return principalLists;
    }

    public List<String> requestGetprincsWithExp(String exp) throws KrbException {
        Kadmin remote = new RemoteKadminImpl(innerClient);
        List<String> principalLists = remote.getPrincipals(exp);
        return principalLists;
    }
    
    public void requestExportKeytab(File keytabFile, String principal) throws KrbException {
        Kadmin remote = new RemoteKadminImpl(innerClient);
        remote.exportKeytab(keytabFile, principal);
    }

    public void requestExportKeytab(File keytabFile, List<String> principals) throws KrbException {
        Kadmin remote = new RemoteKadminImpl(innerClient);
        remote.exportKeytab(keytabFile, principals);
    }

    public void requestChangePassword(String principal, String newPassword) throws KrbException {
        Kadmin remote = new RemoteKadminImpl(innerClient);
        remote.changePassword(principal, newPassword);
    }
}
