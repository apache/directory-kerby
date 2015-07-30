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
import org.apache.kerby.kerberos.kerb.admin.Kadmin;
import org.apache.kerby.kerberos.kerb.client.Krb5Conf;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.util.NetworkUtil;

import java.io.File;
import java.io.IOException;

/**
 * A simple KDC server mainly for test usage. It also integrates krb client and
 * kadmin sides for convenience.
 */
public class SimpleKdcServer extends KdcServer {
    private final KrbClient krbClnt;
    private Kadmin kadmin;

    private File workDir;

    public SimpleKdcServer() throws KrbException {
        super();
        this.krbClnt = new KrbClient();

        setKdcRealm("EXAMPLE.COM");
        setKdcHost("localhost");
        setKdcPort(NetworkUtil.getServerPort());
    }

    public void setWorkDir(File workDir) {
        this.workDir = workDir;
    }

    public File getWorkDir() {
        return workDir;
    }

    @Override
    public void setKdcRealm(String realm) {
        super.setKdcRealm(realm);
        krbClnt.setKdcRealm(realm);
    }

    @Override
    public void setKdcHost(String kdcHost) {
        super.setKdcHost(kdcHost);
        krbClnt.setKdcHost(kdcHost);
    }

    @Override
    public void setKdcTcpPort(int kdcTcpPort) {
        super.setKdcTcpPort(kdcTcpPort);
        krbClnt.setKdcTcpPort(kdcTcpPort);
        setAllowTcp(true);
    }

    @Override
    public void setAllowUdp(boolean allowUdp) {
        super.setAllowUdp(allowUdp);
        krbClnt.setAllowUdp(allowUdp);
    }

    @Override
    public void setAllowTcp(boolean allowTcp) {
        super.setAllowTcp(allowTcp);
        krbClnt.setAllowTcp(allowTcp);
    }

    @Override
    public void setKdcUdpPort(int kdcUdpPort) {
        super.setKdcUdpPort(kdcUdpPort);
        krbClnt.setKdcUdpPort(kdcUdpPort);
        setAllowUdp(true);
    }

    @Override
    public void init() throws KrbException {
        super.init();

        kadmin = new Kadmin(getKdcSetting(), getIdentityService());

        kadmin.createBuiltinPrincipals();

        try {
            Krb5Conf krb5Conf = new Krb5Conf(this);
            krb5Conf.initKrb5conf();
        } catch (IOException e) {
            throw new KrbException("Failed to make krb5.conf", e);
        }
    }

    @Override
    public void start() throws KrbException {
        super.start();

        krbClnt.init();
    }

    public KrbClient getKrbClient() {
        return krbClnt;
    }

    /**
     * Get Kadmin operation interface.
     * @return
     */
    public Kadmin getKadmin() {
        return kadmin;
    }

    public void createPrincipal(String principal) throws KrbException {
        kadmin.addPrincipal(principal);
    }

    public void createPrincipal(String principal,
                                String password) throws KrbException {
        kadmin.addPrincipal(principal, password);
    }

    public void createPrincipals(String ... principals) throws KrbException {
        for (String principal : principals) {
            kadmin.addPrincipal(principal);
        }
    }

    /**
     * Creates principals and export their keys to the specified keytab file.
     */
    public void createAndExportPrincipals(File keytabFile,
                                String ... principals) throws KrbException {
        createPrincipals(principals);
        exportPrincipals(keytabFile);
    }

    public void deletePrincipals(String ... principals) throws KrbException {
        for (String principal : principals) {
            deletePrincipal(principal);
        }
    }

    public void deletePrincipal(String principal) throws KrbException {
        kadmin.deletePrincipal(principal);
    }

    public void exportPrincipals(File keytabFile) throws KrbException {
        kadmin.exportKeytab(keytabFile);
    }

    /**
     * Export the keys of the specified principal into keytab file.
     * @param principal
     * @param keytabFile
     * @throws KrbException
     */
    public void exportPrincipal(String principal, File keytabFile) throws KrbException {
        kadmin.exportKeytab(keytabFile, principal);
    }
}
