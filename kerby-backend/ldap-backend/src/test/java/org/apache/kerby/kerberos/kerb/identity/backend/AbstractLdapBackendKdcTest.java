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
package org.apache.kerby.kerberos.kerb.identity.backend;

import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.server.KdcTestBase;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;

public class AbstractLdapBackendKdcTest extends AbstractLdapTestUnit {

    protected static final String BASE_DN = "ou=users,dc=example,dc=com";
    protected static final String ADMIN_DN = "uid=admin,ou=system";
    protected static final String ADMIN_PW = "secret";

    /** The used DirectoryService instance */
    private static DirectoryService service;

    protected LdapKdcTestBase test = new LdapKdcTestBase();

    public static DirectoryService getDirectoryService() {
        return service;
    }


    public static void setDirectoryService(DirectoryService service) {
        AbstractLdapBackendKdcTest.service = service;
    }

    protected class LdapKdcTestBase extends KdcTestBase {
        private int port;

        public void setPort(int port) {
            this.port = port;
        }

        @Override
        public SimpleKdcServer getKdcServer() { //NOPMD
            return super.getKdcServer();
        }
        @Override
        public KrbClient getKrbClient() { //NOPMD
            return super.getKrbClient();
        }
        @Override
        public String getClientPrincipal() { //NOPMD
            return super.getClientPrincipal();
        }
        @Override
        public String getClientPassword() { //NOPMD
            return super.getClientPassword();
        }
        @Override
        public String getServerPrincipal() { //NOPMD
            return super.getServerPrincipal();
        }
        @Override
        public void prepareKdc() throws KrbException {
            BackendConfig backendConfig = getKdcServer().getBackendConfig();
            backendConfig.setString("host", "localhost");
            backendConfig.setString("admin_dn", ADMIN_DN);
            backendConfig.setString("admin_pw", ADMIN_PW);
            backendConfig.setString("base_dn", BASE_DN);
            backendConfig.setInt("port", port);
            backendConfig.setString(KdcConfigKey.KDC_IDENTITY_BACKEND,
                    "org.apache.kerby.kerberos.kdc.identitybackend.LdapIdentityBackend");
            super.prepareKdc();
        }
    }
}
