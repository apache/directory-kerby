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

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.util.GeneralizedTime;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.shared.kerberos.KerberosAttribute;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.AbstractIdentityBackend;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * An LDAP based backend implementation.
 */
public class LdapIdentityBackend extends AbstractIdentityBackend {
    //The LdapConnection, may be LdapNetworkConnection or LdapCoreSessionConnection
    private LdapConnection connection;
    //This is used as a flag to represent the connection whether is
    // LdapNetworkConnection object or not
    private boolean isLdapNetworkConnection;
    private static final Logger LOG = LoggerFactory.getLogger(LdapIdentityBackend.class);

    public LdapIdentityBackend() {
        this.isLdapNetworkConnection = true;
    }

    /**
     * Constructing an instance using specified config that contains anything
     * to be used to initialize an LdapConnection and necessary baseDn.
     * @param config . The config is used to config the backend.
     */
    public LdapIdentityBackend(Config config) {
        setConfig(config);
        this.isLdapNetworkConnection = true;
    }

    /**
     * Constructing an instance using a LdapConnection and a specified config
     * that contains anything to be used to initialize a necessary baseDn.
     * @param config The config is used to config the backend
     * @param connection The connection to be used to handle the operations,
     *                   may be a LdapNetworkConnection or a LdapCoreSessionConnection.
     */
    public LdapIdentityBackend(Config config,
                               LdapConnection connection) {
        setConfig(config);
        this.connection = connection;
    }

    /**
     * Start the connection for the initialize()
     */
    private void startConnection() throws LdapException {
        if (isLdapNetworkConnection == true) {
            this.connection = new LdapNetworkConnection(getConfig().getString("host"),
                    getConfig().getInt("port"));
        }
        connection.bind(getConfig().getString("admin_dn"),
                getConfig().getString("admin_pw"));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doInitialize() throws KrbException {
        LOG.info("Initializing the Ldap identity backend.");
        try {
            startConnection();
        } catch (LdapException e) {
            LOG.error("Failed to start connection with LDAP", e);
            throw new KrbException("Failed to start connection with LDAP", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doStop() throws KrbException {
        try {
            closeConnection();
        } catch (IOException e) {
            LOG.error("Failed to close connection with LDAP", e);
            throw new KrbException("Failed to close connection with LDAP", e);
        }
         LOG.info("closed connection with LDAP.");
    }

    /**
     * Close the connection for stop()
     */
    private void closeConnection() throws IOException {
        if (connection.isConnected()) {
            connection.close();
        }
    }

    /**
     * Convert a KerberosTime type obeject to a generalized time form of String
     * @param kerberosTime The kerberostime to convert
     */
    private String toGeneralizedTime(KerberosTime kerberosTime) {
        GeneralizedTime generalizedTime = new GeneralizedTime(kerberosTime.getValue());
        return generalizedTime.toString();
    }

    /**
     * An inner class, used to encapsulate key information
     */
    static class KeysInfo {
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

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) throws KrbException {
        String principalName = identity.getPrincipalName();
        String[] names = principalName.split("@");
        Entry entry = new DefaultEntry();
        KeysInfo keysInfo = new KeysInfo(identity);
        try {
            Dn dn = toDn(principalName);
            entry.setDn(dn);
            entry.add("objectClass", "top", "person", "inetOrgPerson",
                    "krb5principal", "krb5kdcentry");
            entry.add("cn", names[0]);
            entry.add("sn", names[0]);
            entry.add(KerberosAttribute.KRB5_KEY_AT, keysInfo.getKeys());
            entry.add("krb5EncryptionType", keysInfo.getEtypes());
            entry.add(KerberosAttribute.KRB5_PRINCIPAL_NAME_AT, principalName);
            entry.add(KerberosAttribute.KRB5_KEY_VERSION_NUMBER_AT,
                    identity.getKeyVersion() + "");
            entry.add("krb5KDCFlags", "" + identity.getKdcFlags());
            entry.add(KerberosAttribute.KRB5_ACCOUNT_DISABLED_AT, ""
                    + identity.isDisabled());
            entry.add("createTimestamp",
                    toGeneralizedTime(identity.getCreatedTime()));
            entry.add(KerberosAttribute.KRB5_ACCOUNT_LOCKEDOUT_AT, ""
                    + identity.isLocked());
            entry.add(KerberosAttribute.KRB5_ACCOUNT_EXPIRATION_TIME_AT,
                    toGeneralizedTime(identity.getExpireTime()));
            connection.add(entry);
        } catch (LdapInvalidDnException e) {
            LOG.error("Error occurred while adding identity", e);
            throw new KrbException("Failed to add identity", e);
        } catch (LdapException e) {
            LOG.error("Error occurred while adding identity", e);
            throw new KrbException("Failed to add identity", e);
        }
        return getIdentity(principalName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doGetIdentity(String principalName) throws KrbException {
        KrbIdentity krbIdentity = new KrbIdentity(principalName);
        try {
            Dn dn = toDn(principalName);
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
            throw new KrbException("Failed to retrieve identity", e);
        } catch (ParseException e) {
            throw new KrbException("Failed to retrieve identity", e);
        } catch (IOException e) {
            throw new KrbException("Failed to retrieve identity", e);
        }

        return krbIdentity;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) throws KrbException {
        String principalName = identity.getPrincipalName();
        KeysInfo keysInfo = new KeysInfo(identity);
        try {
            Dn dn = toDn(principalName);
            ModifyRequest modifyRequest = new ModifyRequestImpl();
            modifyRequest.setName(dn);
            modifyRequest.replace(KerberosAttribute.KRB5_KEY_VERSION_NUMBER_AT,
                    "" + identity.getKeyVersion());
            modifyRequest.replace(KerberosAttribute.KRB5_KEY_AT, keysInfo.getKeys());
            modifyRequest.replace("krb5EncryptionType", keysInfo.getEtypes());
            modifyRequest.replace(KerberosAttribute.KRB5_PRINCIPAL_NAME_AT,
                    identity.getPrincipalName());
            modifyRequest.replace(KerberosAttribute.KRB5_ACCOUNT_EXPIRATION_TIME_AT,
                    toGeneralizedTime(identity.getExpireTime()));
            modifyRequest.replace(KerberosAttribute.KRB5_ACCOUNT_DISABLED_AT, ""
                    + identity.isDisabled());
            modifyRequest.replace("krb5KDCFlags", "" + identity.getKdcFlags());
            modifyRequest.replace(KerberosAttribute.KRB5_ACCOUNT_LOCKEDOUT_AT, ""
                    + identity.isLocked());
            connection.modify(modifyRequest);
        } catch (LdapException e) {
            LOG.error("Error occurred while updating identity: " + principalName, e);
            throw new KrbException("Failed to update identity", e);
        }

        return getIdentity(principalName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doDeleteIdentity(String principalName) throws KrbException {
        try {
            Dn dn = toDn(principalName);
            connection.delete(dn);
        } catch (LdapException e) {
            LOG.error("Error occurred while deleting identity: " + principalName);
            throw new KrbException("Failed to remove identity", e);
        }
    }

    /**
     * Used to convert a dn of String to a Dn object
     * @param principalName The principal name to be convert.
     * @return
     * @throws org.apache.directory.api.ldap.model.exception.LdapInvalidDnException if a remote exception occurs.
     */
    private Dn toDn(String principalName) throws LdapInvalidDnException {
        String[] names = principalName.split("@");
        String uid = names[0];
        Dn dn = new Dn(new Rdn("uid", uid), new Dn(getConfig().getString("base_dn")));
        return dn;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Iterable<String> doGetIdentities() {
        List<String> identityNames = new ArrayList<>();
        EntryCursor cursor;
        Entry entry;
        try {
            cursor = connection.search(getConfig().getString("base_dn"),
                    "(objectclass=*)", SearchScope.ONELEVEL, KerberosAttribute.KRB5_PRINCIPAL_NAME_AT);
            if (cursor == null) {
                return null;
            }
            while (cursor.next()) {
                entry = cursor.get();
                identityNames.add(entry.get(KerberosAttribute.KRB5_PRINCIPAL_NAME_AT).getString());
            }
            cursor.close();
            Collections.sort(identityNames);
        } catch (LdapException e) {
            e.printStackTrace();
        } catch (CursorException e) {
            e.printStackTrace();
        }
        return identityNames;
    }
}
