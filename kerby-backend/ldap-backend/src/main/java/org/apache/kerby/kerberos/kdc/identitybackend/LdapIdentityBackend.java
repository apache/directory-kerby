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
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
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
import org.apache.kerby.kerberos.kerb.identity.backend.AbstractIdentityBackend;
import org.apache.kerby.kerberos.kerb.request.KrbIdentity;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

/**
 * An LDAP based backend implementation.
 */
public class LdapIdentityBackend extends AbstractIdentityBackend {
    private int currentConnectionIndex = 0;
    private Map<String, LdapConnection> connections = new HashMap<>();

    //The LdapConnection, may be LdapNetworkConnection or LdapCoreSessionConnection
    private LdapConnection connection;
    private String[] hosts;
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
        if (isHa()) {
            throw new IllegalArgumentException("Only one ldap connection provided, but two needed "
                    + "when set ha hosts[" + config.getString("host") + "]");
        }
        this.connection = connection;
        String hostConfig = getConfig().getString("host");
        hosts = new String[]{hostConfig};
        connections.put(hostConfig, connection);
    }

    public LdapIdentityBackend(Config config, Map<String, LdapConnection> connections) {
        setConfig(config);
        String hostConfig = getConfig().getString("host");
        hosts = hostConfig.trim().split(",");
        if (hosts.length > 2) {
            throw new IllegalArgumentException("More than two ldap hosts is not supported.");
        }
        if (hosts.length != connections.size()) {
            throw new IllegalArgumentException("Number of ldap hosts[" + hosts.length
                    + "] not equal to ldap connections[" + connections.size() + "].");
        }
        this.connections = new HashMap<>(connections);
        connection = connections.get(hosts[currentConnectionIndex]);
    }

    /**
     * Start the connection for the initialize()
     */
    private void startConnection() throws LdapException {
        if (isLdapNetworkConnection) {
            String hostConfig = getConfig().getString("host");
            hosts = hostConfig.trim().split(",");
            if (hosts.length > 2) {
                throw new IllegalArgumentException("More than two ldap hosts is not supported.");
            }
            for (String host: hosts) {
                LdapConnection connection =
                        new LdapNetworkConnection(host, getConfig().getInt("port"));
                connections.put(host, connection);
            }
            String currentHost = hosts[currentConnectionIndex];
            connection = connections.get(currentHost);
        }
        for (LdapConnection connection: connections.values()) {
            connection.bind(getConfig().getString("admin_dn"),
                    getConfig().getString("admin_pw"));
        }
        LOG.info("Start connection with ldap host[" + getConfig().getString("host") + "]");
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
        IOException cause = null;
        for (Map.Entry<String, LdapConnection> entry: connections.entrySet()) {
            LdapConnection connection = entry.getValue();
            try {
                if (connection.isConnected()) {
                    connection.close();
                }
            } catch (IOException e) {
                LOG.error("Catch exception when close connection with host[" + entry.getKey() + "].");
                if (cause == null) {
                    cause = e;
                } else {
                    cause.addSuppressed(e);
                }
            }
        }
        if (cause != null) {
            throw cause;
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

        KeysInfo(KrbIdentity identity) throws KrbException {
            Map<EncryptionType, EncryptionKey> keymap = identity.getKeys();
            this.etypes = new String[keymap.size()];
            this.keys = new byte[keymap.size()][];
            this.kvnos = new String[keymap.size()];
            int i = 0;
            for (Map.Entry<EncryptionType, EncryptionKey> entryKey : keymap.entrySet()) {
                etypes[i] = entryKey.getKey().getValue() + "";
                try {
                    keys[i] = entryKey.getValue().encode();
                } catch (IOException e) {
                    throw new KrbException("encode key failed", e);
                }
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
            entry.add("uid", names[0]);
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
            entry.add(KerberosAttribute.KRB5_ACCOUNT_LOCKEDOUT_AT, ""
                    + identity.isLocked());
            entry.add(KerberosAttribute.KRB5_ACCOUNT_EXPIRATION_TIME_AT,
                    toGeneralizedTime(identity.getExpireTime()));
            new FailoverInvocationHandler<Void>() {
                @Override
                public Void execute() throws LdapException {
                    connection.add(entry);
                    return null;
                }
            }.run();
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
        String searchFilter =
            String.format("(&(objectclass=krb5principal)(krb5PrincipalName=%s))", principalName);
        try {
            EntryCursor cursor = new FailoverInvocationHandler<EntryCursor>() {
                @Override
                public EntryCursor execute() throws LdapException {
                    return connection.search(getConfig().getString("base_dn"), searchFilter,
                        SearchScope.SUBTREE, "dn");
                }
            }.run();

            // there should be at most one entry with this principal name
            if (cursor == null || !cursor.next()) {
                return null;
            }
            Dn dn = cursor.get().getDn();
            cursor.close();

            Entry entry = new FailoverInvocationHandler<Entry>() {
                @Override
                public Entry execute() throws LdapException {
                    return connection.lookup(dn, "*", "+");
                }
            }.run();
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
        } catch (CursorException e) {
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
            new FailoverInvocationHandler<Void>() {
                @Override
                public Void execute() throws LdapException {
                    connection.modify(modifyRequest);
                    return null;
                }
            }.run();
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
            new FailoverInvocationHandler<Void>() {
                @Override
                public Void execute() throws LdapException {
                    connection.delete(dn);
                    return null;
                }
            }.run();
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
     * @throws LdapInvalidAttributeValueException 
     */
    private Dn toDn(String principalName) throws LdapInvalidDnException, LdapInvalidAttributeValueException {
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
            cursor = new FailoverInvocationHandler<EntryCursor>() {
                @Override
                public EntryCursor execute() throws LdapException {
                    return connection.search(getConfig().getString("base_dn"), "(objectclass=krb5principal)",
                        SearchScope.SUBTREE, KerberosAttribute.KRB5_PRINCIPAL_NAME_AT);
                }
            }.run();
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
            LOG.error("With LdapException when LdapConnection searching. " + e);
        } catch (CursorException e) {
            LOG.error("With CursorException when EntryCursor getting. " + e);
        } catch (IOException e) {
            LOG.error("With IOException when closing EntryCursor. " + e);
        }
        return identityNames;
    }

    private void performFailover() {
        currentConnectionIndex = (currentConnectionIndex + 1) % hosts.length;
        String host = hosts[currentConnectionIndex];
        connection = connections.get(host);
    }

    private boolean isHa() {
        String host = getConfig().getString("host");
        if (host != null) {
            return host.trim().split(",").length == 2;
        }
        return false;
    }

    abstract class FailoverInvocationHandler<T> {
        public abstract T execute() throws LdapException;

        public T run() throws LdapException {
            try {
                return execute();
            } catch (LdapException e) {
                if (!isHa()) {
                    throw e;
                }
                String host = hosts[currentConnectionIndex];
                LOG.error("Catch exception with ldap host[" + host + "].", e);
                performFailover();
                host = hosts[currentConnectionIndex];
                LOG.info("Failover to ldap host:" + host + ".");
                return execute();
            }
        }
    }
}
