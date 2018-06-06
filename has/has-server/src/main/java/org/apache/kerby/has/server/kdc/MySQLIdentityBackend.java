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
package org.apache.kerby.has.server.kdc;

import com.alibaba.druid.pool.DruidDataSource;
import org.apache.commons.dbutils.DbUtils;
import org.apache.directory.api.util.GeneralizedTime;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.backend.AbstractIdentityBackend;
import org.apache.kerby.kerberos.kerb.request.KrbIdentity;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.ResultSet;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import javax.sql.rowset.serial.SerialBlob;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.text.ParseException;

/**
 * A MySQL based backend implementation.
 */
public class MySQLIdentityBackend extends AbstractIdentityBackend {
    private String keyInfoTable;
    private String identityTable;
    private static DruidDataSource dataSource = null;
    private static final Logger LOG = LoggerFactory.getLogger(MySQLIdentityBackend.class);

    /**
     * Constructing an instance using specified config that contains anything
     * to be used to initialize an MySQL Backend.
     *
     * @param config used to config the backend
     */
    public MySQLIdentityBackend(final Config config) {
        setConfig(config);
    }

    public MySQLIdentityBackend() {
    }

    /**
     * Create data base connection pool.
     * @throws SQLException e
     */
    private void initializeDataSource(
        String driver, String url, String user, String password) throws SQLException {
        dataSource = new DruidDataSource();
        dataSource.setDriverClassName(driver);
        dataSource.setUrl(url);
        dataSource.setUsername(user);
        dataSource.setPassword(password);

        dataSource.setInitialSize(10);
        dataSource.setMinIdle(3);
        dataSource.setMaxActive(80);
        dataSource.setMaxWait(6000);
        dataSource.setTestWhileIdle(true);
        dataSource.setValidationQuery("SELECT 1");
        dataSource.setTestOnBorrow(false);
        dataSource.setTestOnReturn(false);
        dataSource.setRemoveAbandoned(true);
        dataSource.setRemoveAbandonedTimeout(180);
        dataSource.setLogAbandoned(true);
        dataSource.setMinEvictableIdleTimeMillis(300000);
        dataSource.setTimeBetweenEvictionRunsMillis(90000);
        dataSource.setPoolPreparedStatements(true);
        dataSource.setMaxOpenPreparedStatements(20);
        dataSource.setMaxPoolPreparedStatementPerConnectionSize(30);
        dataSource.setAsyncInit(true);
        dataSource.setFilters("stat");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doInitialize() throws KrbException {
        LOG.info("Initializing the MySQL identity backend.");

        // Initialize data base connection pool
        if (MySQLIdentityBackend.dataSource == null) {
            String driver = getConfig().getString(MySQLConfKey.MYSQL_DRIVER, true);
            String user = getConfig().getString(MySQLConfKey.MYSQL_USER, true);
            String password = getConfig().getString(MySQLConfKey.MYSQL_PASSWORD, true);

            String urlString = getConfig().getString(MySQLConfKey.MYSQL_URL, true);
            if (urlString == null || urlString.isEmpty()) {
                urlString = getBackendConfig().getString(MySQLConfKey.MYSQL_URL, true);
            }

            try {
                initializeDataSource(driver, urlString, user, password);
            } catch (SQLException e) {
                LOG.error("Failed to initialize data source. " + e.toString());
                throw new KrbException("Failed to initialize data source.", e);
            }
        }

        Connection connection = null;
        PreparedStatement preInitialize = null;
        PreparedStatement preKdcRealm = null;
        ResultSet resKdcRealm = null;
        PreparedStatement preIdentity = null;
        PreparedStatement preKey = null;
        try {
            connection = dataSource.getConnection();

            // Set initialized for kdc config
            String stmInitialize = "UPDATE `kdc_config` SET initialized = true WHERE id = 1";
            preInitialize = connection.prepareStatement(stmInitialize);
            preInitialize.executeUpdate();

            // Get identity table name according to realm of kdc
            String stmKdcRealm = "SELECT realm FROM `kdc_config`";
            preKdcRealm = connection.prepareStatement(stmKdcRealm);
            resKdcRealm = preKdcRealm.executeQuery();
            if (resKdcRealm.next()) {
                String realm = resKdcRealm.getString("realm").toLowerCase();
                identityTable = "`" + realm + "_identity" + "`";
                keyInfoTable = "`" + realm + "_key" + "`";
            } else {
                throw new KrbException("Failed to get kdc config.");
            }

            // Create identity table
            String stmIdentity = "CREATE TABLE IF NOT EXISTS " + identityTable
                + " (principal varchar(255) NOT NULL, key_version INTEGER "
                + "DEFAULT 1, kdc_flags INTEGER DEFAULT 0, disabled bool "
                + "DEFAULT NULL, locked bool DEFAULT NULL, expire_time "
                + "VARCHAR(255) DEFAULT NULL, created_time VARCHAR(255) "
                + "DEFAULT NULL, PRIMARY KEY (principal) ) ENGINE=INNODB "
                + "DEFAULT CHARSET=utf8;";
            preIdentity = connection.prepareStatement(stmIdentity);
            preIdentity.executeUpdate();

            // Create key table
            String stmKey = "CREATE TABLE IF NOT EXISTS " + keyInfoTable
                + " (key_id INTEGER NOT NULL AUTO_INCREMENT, key_type "
                + "VARCHAR(255) DEFAULT NULL, kvno INTEGER DEFAULT -1, "
                + "key_value BLOB DEFAULT NULL, principal VARCHAR(255) NOT NULL,"
                + "PRIMARY KEY (key_id), INDEX (principal), FOREIGN KEY "
                + "(principal) REFERENCES " + identityTable + "(principal) "
                + ") ENGINE=INNODB DEFAULT CHARSET=utf8;";
            preKey = connection.prepareStatement(stmKey);
            preKey.executeUpdate();

        } catch (SQLException e) {
            LOG.error("Error occurred while initialize MySQL backend.", e);
            throw new KrbException("Failed to create table in database. ", e);
        } finally {
            DbUtils.closeQuietly(preInitialize);
            DbUtils.closeQuietly(preKdcRealm);
            DbUtils.closeQuietly(resKdcRealm);
            DbUtils.closeQuietly(preIdentity);
            DbUtils.closeQuietly(preKey);
            DbUtils.closeQuietly(connection);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doStop() throws KrbException {
        if (dataSource == null) {
            return;
        }
        dataSource.close();
        if (dataSource.isClosed()) {
            LOG.info("Succeeded in closing connection with MySQL.");
        } else {
            throw new KrbException("Failed to close connection with MySQL.");
        }
    }

    /**
     * Convert a KerberosTime type object to a generalized time form of String.
     * @param kerberosTime The kerberos time to convert
     */
    private String toGeneralizedTime(final KerberosTime kerberosTime) {
        GeneralizedTime generalizedTime = new GeneralizedTime(kerberosTime.getValue());
        return generalizedTime.toString();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) throws KrbException {
        String principalName = identity.getPrincipalName();
        int keyVersion = identity.getKeyVersion();
        int kdcFlags = identity.getKdcFlags();
        boolean disabled = identity.isDisabled();
        boolean locked = identity.isLocked();
        String createdTime = toGeneralizedTime(identity.getCreatedTime());
        String expireTime = toGeneralizedTime(identity.getExpireTime());
        Map<EncryptionType, EncryptionKey> keys = identity.getKeys();

        Connection connection = null;
        PreparedStatement preIdentity = null;
        PreparedStatement preKey = null;

        KrbIdentity duplicateIdentity = doGetIdentity(principalName);
        if (duplicateIdentity != null) {
            LOG.warn("The identity maybe duplicate.");

            return duplicateIdentity;
        } else {
            try {
                connection = dataSource.getConnection();
                connection.setAutoCommit(false);

                // Insert identity to identity table
                String stmIdentity = "insert into " + identityTable
                    + " (principal, key_version, kdc_flags, disabled, locked,"
                    + " created_time, expire_time) values(?, ?, ?, ?, ?, ?, ?)";
                preIdentity = connection.prepareStatement(stmIdentity);
                preIdentity.setString(1, principalName);
                preIdentity.setInt(2, keyVersion);
                preIdentity.setInt(3, kdcFlags);
                preIdentity.setBoolean(4, disabled);
                preIdentity.setBoolean(5, locked);
                preIdentity.setString(6, createdTime);
                preIdentity.setString(7, expireTime);
                preIdentity.executeUpdate();

                // Insert keys to key table
                for (Map.Entry<EncryptionType, EncryptionKey> entry : keys.entrySet()) {
                    String stmKey = "insert into " + keyInfoTable
                        + " (key_type, kvno, key_value, principal) values(?, ?, ?, ?)";
                    preKey = connection.prepareStatement(stmKey);
                    preKey.setString(1, entry.getKey().getName());
                    preKey.setInt(2, entry.getValue().getKvno());
                    preKey.setBlob(3, new SerialBlob(entry.getValue().getKeyData()));
                    preKey.setString(4, principalName);
                    preKey.executeUpdate();
                }

                connection.commit();
                return identity;
            } catch (SQLException e) {
                try {
                    LOG.info("Transaction is being rolled back.");
                    if (connection != null) {
                        connection.rollback();
                    }
                } catch (SQLException ex) {
                    throw new KrbException("Transaction roll back failed. ", ex);
                }
                LOG.error("Error occurred while adding identity.");
                throw new KrbException("Failed to add identity. ", e);
            } finally {
                DbUtils.closeQuietly(preIdentity);
                DbUtils.closeQuietly(preKey);
                DbUtils.closeQuietly(connection);
            }
        }
    }

    /**
     * Create kerberos time.
     * @param generalizedTime generalized time
     * @throws ParseException parse exception
     */
    private KerberosTime createKerberosTime(final String generalizedTime) throws ParseException {
        long time = new GeneralizedTime(generalizedTime).getTime();
        return new KerberosTime(time);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doGetIdentity(final String principalName) throws KrbException {
        KrbIdentity krbIdentity = null;

        Connection connection = null;
        PreparedStatement preIdentity = null;
        ResultSet resIdentity = null;
        try {
            connection = dataSource.getConnection();

            // Get identity from identity and key table
            String stmIdentity = String.format("SELECT * FROM %s a left join %s b on "
                + "a.principal = b.principal where a.principal = ?", identityTable, keyInfoTable);
            preIdentity = connection.prepareStatement(stmIdentity);
            preIdentity.setString(1, principalName);
            resIdentity = preIdentity.executeQuery();
            List<EncryptionKey> keys = new ArrayList<>();

            if (resIdentity.isBeforeFirst()) {
                while (resIdentity.next()) {
                    if (krbIdentity == null) {
                        krbIdentity = new KrbIdentity(principalName);
                        krbIdentity.setKeyVersion(resIdentity.getInt("key_version"));
                        krbIdentity.setKdcFlags(resIdentity.getInt("kdc_flags"));
                        krbIdentity.setDisabled(resIdentity.getBoolean("disabled"));
                        krbIdentity.setLocked(resIdentity.getBoolean("locked"));
                        krbIdentity.setCreatedTime(createKerberosTime(resIdentity.getString("created_time")));
                        krbIdentity.setExpireTime(createKerberosTime(resIdentity.getString("expire_time")));
                    }

                    // Get key info
                    int kvno = resIdentity.getInt("kvno");
                    String keyType = resIdentity.getString("key_type");
                    EncryptionType eType = EncryptionType.fromName(keyType);
                    byte[] keyValue = resIdentity.getBytes("key_value");
                    EncryptionKey key = new EncryptionKey(eType, keyValue, kvno);
                    keys.add(key);
                }
                if (krbIdentity != null && keys.size() > 0) {
                    krbIdentity.addKeys(keys);
                }
                return krbIdentity;
            } else {
                return null;
            }
        } catch (SQLException e) {
            LOG.error("Error occurred while getting identity. " + e.toString());
            throw new KrbException("Failed to get identity. ", e);
        } catch (ParseException e) {
            LOG.error("Failed to get identity. " + e.toString());
            throw new KrbException("Failed to get identity. ", e);
        } finally {
            DbUtils.closeQuietly(preIdentity);
            DbUtils.closeQuietly(resIdentity);
            DbUtils.closeQuietly(connection);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) throws KrbException {
        String principalName = identity.getPrincipalName();
        try {
            // Delete old identity
            doDeleteIdentity(principalName);
            // Insert new identity
            doAddIdentity(identity);
        } catch (KrbException e) {
            LOG.error("Error occurred while updating identity: " + principalName);
            throw new KrbException("Failed to update identity. ", e);
        }

        return getIdentity(principalName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doDeleteIdentity(String principalName) throws KrbException {
        Connection connection = null;
        PreparedStatement preKey = null;
        PreparedStatement preIdentity = null;
        try {
            connection = dataSource.getConnection();
            connection.setAutoCommit(false);

            // Delete keys from key table
            String stmKey = "DELETE FROM  " + keyInfoTable + " where principal = ?";
            preKey = connection.prepareStatement(stmKey);
            preKey.setString(1, principalName);
            preKey.executeUpdate();

            // Delete identity from identity table
            String stmIdentity = "DELETE FROM " + identityTable + " where principal = ? ";
            preIdentity = connection.prepareStatement(stmIdentity);
            preIdentity.setString(1, principalName);
            preIdentity.executeUpdate();

            connection.commit();
        } catch (SQLException e) {
            try {
                LOG.warn("Transaction is being rolled back.");
                if (connection != null) {
                    connection.rollback();
                }
            } catch (SQLException ex) {
                throw new KrbException("Transaction roll back failed. ", ex);
            }
            LOG.error("Error occurred while deleting identity.");
            throw new KrbException("Failed to delete identity. ", e);
        } finally {
            DbUtils.closeQuietly(preIdentity);
            DbUtils.closeQuietly(preKey);
            DbUtils.closeQuietly(connection);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Iterable<String> doGetIdentities() throws KrbException {
        List<String> identityNames = new ArrayList<>();
        Connection connection = null;
        PreparedStatement preSmt = null;
        ResultSet result = null;
        try {
            connection = dataSource.getConnection();
            String statement = "SELECT * FROM " + identityTable;
            preSmt = connection.prepareStatement(statement);
            result = preSmt.executeQuery();
            while (result.next()) {
                identityNames.add(result.getString("principal"));
            }
            result.close();
            preSmt.close();
        } catch (SQLException e) {
            LOG.error("Error occurred while getting identities.", e);
            throw new KrbException("Failed to get identities. ", e);
        } finally {
            DbUtils.closeQuietly(preSmt);
            DbUtils.closeQuietly(result);
            DbUtils.closeQuietly(connection);
        }

        return identityNames;
    }
}
