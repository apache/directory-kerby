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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.client.Krb5Conf;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbPkinitClient;
import org.apache.kerby.kerberos.kerb.client.KrbTokenClient;
import org.apache.kerby.util.NetworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

/**
 * A simple KDC server mainly for test usage. It also integrates krb client and
 * kadmin sides for convenience.
 */
public class SimpleKdcServer extends KdcServer {
    private static final Logger LOG =
        LoggerFactory.getLogger(SimpleKdcServer.class);
    private final KrbClient krbClnt;
    private LocalKadmin kadmin;
    private Krb5Conf krb5Conf;
    private File workDir;

    private KrbPkinitClient pkinitClient;
    private KrbTokenClient tokenClient;

    /**
     * Default constructor.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     */
    public SimpleKdcServer() throws KrbException {
        this(new KrbConfig());

        setKdcRealm("EXAMPLE.COM");
        setKdcHost("localhost");
        setKdcPort(NetworkUtil.getServerPort());
    }

    public SimpleKdcServer(KrbConfig krbConfig) {
        super();
        this.krbClnt = new KrbClient(krbConfig);
    }

    public SimpleKdcServer(File confDir, KrbConfig krbConfig) throws KrbException {
        super(confDir);
        this.krbClnt = new KrbClient(krbConfig);
    }

    public synchronized void setWorkDir(File workDir) {
        this.workDir = workDir;
    }

    public synchronized File getWorkDir() {
        return workDir;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized void setKdcRealm(String realm) {
        super.setKdcRealm(realm);
        krbClnt.setKdcRealm(realm);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized void setKdcHost(String kdcHost) {
        super.setKdcHost(kdcHost);
        krbClnt.setKdcHost(kdcHost);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized void setKdcTcpPort(int kdcTcpPort) {
        super.setKdcTcpPort(kdcTcpPort);
        krbClnt.setKdcTcpPort(kdcTcpPort);
        setAllowTcp(true);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized void setAllowUdp(boolean allowUdp) {
        super.setAllowUdp(allowUdp);
        krbClnt.setAllowUdp(allowUdp);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized void setAllowTcp(boolean allowTcp) {
        super.setAllowTcp(allowTcp);
        krbClnt.setAllowTcp(allowTcp);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized void setKdcUdpPort(int kdcUdpPort) {
        super.setKdcUdpPort(kdcUdpPort);
        krbClnt.setKdcUdpPort(kdcUdpPort);
        setAllowUdp(true);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized void init() throws KrbException {
        super.init();

        kadmin = new LocalKadminImpl(getKdcSetting(), getIdentityService());

        kadmin.createBuiltinPrincipals();

        try {
            krb5Conf = new Krb5Conf(this);
            krb5Conf.initKrb5conf();
        } catch (IOException e) {
            throw new KrbException("Failed to make krb5.conf", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized void start() throws KrbException {
        super.start();

        krbClnt.init();
    }

    /**
     * Get krb client.
     * @return KrbClient
     */
    public synchronized KrbClient getKrbClient() {
        return krbClnt;
    }

    /**
     * @return PKINIT client
     */
    public synchronized KrbPkinitClient getPkinitClient() {
        if (pkinitClient == null) {
            pkinitClient = new KrbPkinitClient(krbClnt);
        }
        return pkinitClient;
    }

    /**
     * @return Token client
     */
    public synchronized KrbTokenClient getTokenClient() {
        if (tokenClient == null) {
            tokenClient = new KrbTokenClient(krbClnt);
        }
        return tokenClient;
    }

    /**
     * Get Kadmin operation interface.
     * @return Kadmin
     */
    public synchronized LocalKadmin getKadmin() {
        return kadmin;
    }


    /**
     * Create principal with principal name.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     * @param principal The principal name
     */
    public synchronized void createPrincipal(String principal) throws KrbException {
        kadmin.addPrincipal(principal);
    }

    /**
     * Create principal with principal name and password.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     * @param principal The principal name
     * @param password The password to create keys
     */
    public synchronized void createPrincipal(String principal,
                                String password) throws KrbException {
        kadmin.addPrincipal(principal, password);
    }

    /**
     * Create principals.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     * @param principals The principal list
     */
    public synchronized void createPrincipals(String ... principals) throws KrbException {
        for (String principal : principals) {
            kadmin.addPrincipal(principal);
        }
    }

    /**
     * Creates principals and export their keys to the specified keytab file.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     * @param keytabFile The keytab file to store principal keys
     * @param principals The principals to be create
     */
    public synchronized void createAndExportPrincipals(File keytabFile,
                                String ... principals) throws KrbException {
        createPrincipals(principals);
        exportPrincipals(keytabFile);
    }

    /**
     * Delete principals.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     * @param principals The principals to be delete
     */
    public synchronized void deletePrincipals(String ... principals) throws KrbException {
        for (String principal : principals) {
            deletePrincipal(principal);
        }
    }

    /**
     * Delete principal.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     * @param principal The principal to be delete
     */
    public synchronized void deletePrincipal(String principal) throws KrbException {
        kadmin.deletePrincipal(principal);
    }

    /**
     * Export principals to keytab file.
     *
     * @param keytabFile The keytab file
     * @throws KrbException e
     */
    public synchronized void exportPrincipals(File keytabFile) throws KrbException {
        kadmin.exportKeytab(keytabFile);
    }

    /**
     * Export the keys of the specified principal into keytab file.
     * @param principal principal
     * @param keytabFile keytab file
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     */
    public synchronized void exportPrincipal(String principal, File keytabFile) throws KrbException {
        kadmin.exportKeytab(keytabFile, principal);
    }

    /**
     * @throws KrbException e
     */
    @Override
    public synchronized void stop() throws KrbException {
        super.stop();
        try {
            krb5Conf.deleteKrb5conf();
        } catch (IOException e) {
            LOG.info("Fail to delete krb5 conf. " + e);
        }
    }
}
