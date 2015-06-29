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
import org.apache.kerby.util.NetworkUtil;

import java.io.File;

/**
 * A simple KDC server mainly for test usage.
 */
public class SimpleKdcServer extends KdcServer {
    private Kadmin kadmin;

    /**
     * Prepare KDC configuration.
     */
    public SimpleKdcServer() {
        super();

        KdcConfig kdcConfig = getKdcConfig();
        kdcConfig.setString(KdcConfigKey.KDC_HOST, "localhost");
        kdcConfig.setInt(KdcConfigKey.KDC_PORT, NetworkUtil.getServerPort());
        kdcConfig.setString(KdcConfigKey.KDC_REALM, "EXAMPLE.COM");
    }

    @Override
    public void init() throws KrbException {
        super.init();

        kadmin = new Kadmin(getSetting(), getIdentityService());

        kadmin.createBuiltinPrincipals();
    }

    /**
     * Get Kadmin operation interface.
     * @return
     */
    public Kadmin getKadmin() {
        return kadmin;
    }

    public String getKdcRealm() {
        return getSetting().getKdcRealm();
    }

    public String getKdcHost() {
        return getSetting().getKdcHost();
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
}
