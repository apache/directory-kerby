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
package org.apache.kerby.kerberos.kdc.identitybackend;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.AbstractIdentityBackend;

import java.io.IOException;
import java.util.List;

/**
 * An LDAP based backend implementation.
 *
 */
public class LdapIdentityBackend extends AbstractIdentityBackend {
    private static final String BASE_DN = "ou=users,dc=example,dc=com";//NOPMD
    private static final String ADMIN_DN = "uid=admin,ou=system";
    private LdapNetworkConnection connection;

    public LdapIdentityBackend() {

    }

    /**
     * Constructing an instance using specified config that contains anything
     * to be used to initialize an LdapConnection and necessary baseDn.
     * @param config
     */
    public LdapIdentityBackend(Config config) {
        setConfig(config);
    }

    public void startConnection() throws LdapException {
        this.connection = new LdapNetworkConnection( "localhost",
                getConfig().getInt("port") );
        connection.bind( ADMIN_DN, "secret" );
    }

    @Override
    public void initialize() {
        super.initialize();
        try {
            startConnection();
        } catch (LdapException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void stop() {
        try {
            closeConnection();
        } catch (LdapException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void closeConnection() throws LdapException, IOException {
        if (this.connection.connect()) {
            this.connection.unBind();
            this.connection.close();
        }
    }

    @Override
    protected KrbIdentity doGetIdentity(String principalName) {
        return null;
    }

    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) {
        return null;
    }

    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) {
        return null;
    }

    @Override
    protected void doDeleteIdentity(String principalName) {

    }

    @Override
    public List<String> getIdentities(int start, int limit) {
        return null;
    }

    @Override
    public List<String> getIdentities() {
        return null;
    }
}
