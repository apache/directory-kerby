/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.kerby;

import org.apache.directory.mavibot.btree.BTree;
import org.apache.directory.mavibot.btree.BTreeFactory;
import org.apache.directory.mavibot.btree.BTreeTypeEnum;
import org.apache.directory.mavibot.btree.KeyCursor;
import org.apache.directory.mavibot.btree.PersistedBTreeConfiguration;
import org.apache.directory.mavibot.btree.RecordManager;
import org.apache.directory.mavibot.btree.Tuple;
import org.apache.directory.mavibot.btree.exception.KeyNotFoundException;
import org.apache.directory.mavibot.btree.serializer.StringSerializer;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.AbstractIdentityBackend;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * A backend based on Apache Mavibot(an MVCC BTree library).
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class MavibotBackend extends AbstractIdentityBackend {
    //Name of the database
    private static final String DATA_TREE = "kerby-data";
    // Name of the database file
    private static final String DATABASE_NAME = "kerby-data.db";
    private static final Logger LOG = LoggerFactory.getLogger(MavibotBackend.class);
    //The RecordManager of Mavibot
    private RecordManager rm;
    //The BTree holding all data
    private BTree<String, KrbIdentity> database;
    
    /**
     * Creates a new instance of MavibotBackend.
     *
     * @param location
     *            the File handle pointing to the database file or the directory
     *            where it is present
     * @throws Exception e
     */
    public MavibotBackend(File location) throws Exception {
        String dbPath = location.getAbsolutePath();

        LOG.info("Initializing the mavibot backend");
        
        if (!location.exists() && !location.mkdirs()) {
            throw new KrbException("Can't create location file");
        }

        if (location.isDirectory()) {
            dbPath += File.separator + DATABASE_NAME;
        }

        rm = new RecordManager(dbPath);

        if (rm.getManagedTrees().contains(DATA_TREE)) {
            database = rm.getManagedTree(DATA_TREE);
        } else {
            PersistedBTreeConfiguration<String, KrbIdentity> config =
                    new PersistedBTreeConfiguration<String, KrbIdentity>();
            // _no_ duplicates
            config.setAllowDuplicates(false);
            config.setBtreeType(BTreeTypeEnum.PERSISTED);
            config.setFilePath(dbPath);
            config.setKeySerializer(StringSerializer.INSTANCE);
            config.setName(DATA_TREE);
            config.setValueSerializer(KrbIdentitySerializer.INSTANCE);

            database = BTreeFactory.createPersistedBTree(config);
            rm.manage(database);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Iterable<String> doGetIdentities() throws KrbException {
        List<String> keys = new ArrayList<String>();
        KeyCursor<String> cursor = null;

        try {
            cursor = database.browseKeys();
            while (cursor.hasNext()) {
                keys.add(cursor.next());
            }
        } catch (Exception e) {
            throw new KrbException("Errors occurred while fetching the principals", e);
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }

        return keys;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doGetIdentity(String principalName) throws KrbException {
        try {
            return database.get(principalName);
        } catch (KeyNotFoundException e) {
            LOG.debug("Identity {} doesn't exist", principalName);
            return null;
        } catch (IOException e) {
            throw new KrbException("Failed to get the identity " + principalName);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected synchronized KrbIdentity doAddIdentity(KrbIdentity identity) throws KrbException {
        String p = identity.getPrincipalName();
        try {
            if (database.hasKey(p)) {
                throw new KrbException("Identity already exists " + p);
            }
            
            return database.insert(p, identity);
        } catch (KeyNotFoundException e) {
            throw new KrbException("No such identity exists " + p);
        } catch (IOException e) {
            throw new KrbException("Failed to add the identity " + p);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected synchronized KrbIdentity doUpdateIdentity(KrbIdentity identity) throws KrbException {
        String p = identity.getPrincipalName();
        try {
            if (!database.hasKey(p)) {
                throw new KrbException("No identity found with the principal " + p);
            }
            
            database.delete(p);
            
            return database.insert(p, identity);
        } catch (Exception e) {
            throw new KrbException("Failed to update the identity " + p);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doDeleteIdentity(String principalName) throws KrbException {
        try {
            Tuple<String, KrbIdentity> t = database.delete(principalName);
            if (t == null) {
                throw new KrbException("Not existing, identity = " + principalName);
            }
        } catch (IOException e) {
            throw new KrbException("Failed to delete the identity " + principalName);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doStop() throws KrbException {
        try {
            rm.close();
        } catch (IOException e) {
            throw new KrbException("Failed to close the database", e);
        }
    }
}
