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

import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.AbstractIdentityBackend;

import java.util.List;

/**
 * An LDAP based backend implementation.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapIdentityBackend extends AbstractIdentityBackend {

    /** the connection to the LDAP server */
    // in case of ApacheDS this will be an istance of LdapCoreSessionConnection
    private LdapConnection connection;

    private Dn baseDn;

    /**
     * Constructing an instance using specified config that contains anything to be used
     * to initialize an LdapConnection and necessary baseDn.
     * @param config
     */
    public LdapIdentityBackend(Config config) {
        super(config);
    }

    public LdapIdentityBackend(LdapConnection connection, Dn baseDn) {
        super();
        this.connection = connection;
        this.baseDn = baseDn;
    }

    /**
     * Load identities from file
     */
    public void load() {
        // todo
    }

    /**
     * Persist the updated identities back
     */
    public void save() {
        // todo
    }

    @Override
    public List<KrbIdentity> getIdentities() {
        return null;
    }

    @Override
    public boolean checkIdentity(String name) {
        
        return false;
    }

    @Override
    public KrbIdentity getIdentity(String name) {
        return null;
    }

    @Override
    public void addIdentity(KrbIdentity identity) {

    }

    @Override
    public void updateIdentity(KrbIdentity identity) {

    }

    @Override
    public void deleteIdentity(KrbIdentity identity) {

    }
}
