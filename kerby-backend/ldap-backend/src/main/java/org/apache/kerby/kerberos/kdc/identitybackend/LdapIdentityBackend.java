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

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.util.GeneralizedTime;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.shared.kerberos.KerberosAttribute;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.AbstractIdentityBackend;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import sun.security.krb5.Asn1Exception;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

/**
 * An LDAP based backend implementation.
 *
 */
public class LdapIdentityBackend extends AbstractIdentityBackend {
    private static final String BASE_DN = "ou=users,dc=example,dc=com";
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

    private String toGeneralizedTime(KerberosTime kerberosTime) {
        GeneralizedTime generalizedTime = new GeneralizedTime(kerberosTime.getValue());
        return generalizedTime.toString();
    }

    class KeysInfo{
        private String[] etypes;
        private byte[][] keys;
        private String[] kvnos;

        public KeysInfo(KrbIdentity identity) {
            Map<EncryptionType, EncryptionKey> keymap = identity.getKeys();
            this.etypes = new String[keymap.size()];
            this.keys = new byte[keymap.size()][];
            this.kvnos = new String[keymap.size()];
            int i = 0;
            for (Map.Entry<EncryptionType, EncryptionKey> entryKey : keymap.entrySet()) {
                etypes[i] = entryKey.getKey().getValue() + "";
                keys[i] = entryKey.getValue().encode();
                kvnos[i] = entryKey.getValue().getKvno() + "";
                i++;
            }
        }

        public String[] getEtypes() {
            return etypes;
        }

        public byte[][] getKeys() {
            return keys;
        }

        public String[] getKvnos() {
            return kvnos;
        }
    }

    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) {
        String principalName = identity.getPrincipalName();
        String[] names = principalName.split("@");
        String uid = names[0];
        Entry entry = new DefaultEntry();
        KeysInfo keysInfo = new KeysInfo(identity);
        try {
            Dn dn = new Dn(new Rdn("uid", uid), new Dn(BASE_DN));
            entry.setDn(dn);
            entry.add("objectClass", "top", "person", "inetOrgPerson", "krb5principal", "krb5kdcentry");
            entry.add("cn", names[0]);
            entry.add( "sn", names[0]);
            entry.add(KerberosAttribute.KRB5_KEY_AT, keysInfo.getKeys());
            entry.add( "krb5EncryptionType", keysInfo.getEtypes());
            entry.add( KerberosAttribute.KRB5_PRINCIPAL_NAME_AT, principalName);
            entry.add( KerberosAttribute.KRB5_KEY_VERSION_NUMBER_AT, identity.getKeyVersion() + "");
            entry.add( "krb5KDCFlags", "" + identity.getKdcFlags());
            entry.add( KerberosAttribute.KRB5_ACCOUNT_DISABLED_AT, "" + identity.isDisabled());
            entry.add( "createTimestamp",
                    toGeneralizedTime(identity.getCreatedTime()));
            entry.add(KerberosAttribute.KRB5_ACCOUNT_LOCKEDOUT_AT, "" + identity.isLocked());
            entry.add( KerberosAttribute.KRB5_ACCOUNT_EXPIRATION_TIME_AT,
                    toGeneralizedTime(identity.getExpireTime()));
            connection.add(entry);
        } catch (LdapInvalidDnException e) {
            e.printStackTrace();
        } catch (LdapException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return identity;
    }

    @Override
    protected KrbIdentity doGetIdentity(String principalName) {
        String[] names = principalName.split("@");
        String uid = names[0];
        KrbIdentity krbIdentity = new KrbIdentity(principalName);
        try {
            Dn dn = new Dn(new Rdn("uid", uid), new Dn(BASE_DN));
            Entry entry = connection.lookup(dn, "*", "+");
            if (entry == null) {
                return null;
            }
            LdapIdentityGetHelper getHelper = new LdapIdentityGetHelper(entry);
            krbIdentity.setPrincipal(getHelper.getPrincipalName());
            krbIdentity.setKeyVersion(getHelper.getKeyVersion());
            krbIdentity.addKeys(getHelper.getKeys());
            krbIdentity.setCreatedTime(getHelper.getCreatedTime());
            krbIdentity.setExpireTime(getHelper.getExpireTime());
            krbIdentity.setDisabled(getHelper.getDisabled());
            krbIdentity.setKdcFlags(getHelper.getKdcFlags());
            krbIdentity.setLocked(getHelper.getLocked());
        } catch (LdapException e) {
            e.printStackTrace();
        } catch (Asn1Exception e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return krbIdentity;
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
