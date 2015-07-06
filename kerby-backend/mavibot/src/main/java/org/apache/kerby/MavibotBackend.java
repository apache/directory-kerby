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

import org.apache.directory.mavibot.btree.*;
import org.apache.directory.mavibot.btree.exception.KeyNotFoundException;
import org.apache.directory.mavibot.btree.serializer.StringSerializer;
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
    //The RecordManager of Mavibot
    private RecordManager rm;

    //The BTree holding all data
    private BTree<String, KrbIdentity> database;

    //Name of the database
    private static final String DATA_TREE = "kerby-data";

    // Name of the database file
    private static final String DATABASE_NAME = "kerby-data.db";

    private static final Logger LOG = LoggerFactory.getLogger(MavibotBackend.class);
    
    /**
     * Creates a new instance of MavibotBackend.
     *
     * @param location
     *            the File handle pointing to the database file or the directory
     *            where it is present
     * @throws Exception
     */
    public MavibotBackend(File location) throws Exception {
        String dbPath = location.getAbsolutePath();

        LOG.info("Initializing the mavibot backend");
        
        if (!location.exists()) {
            location.mkdirs();
        }

        if (location.isDirectory()) {
            dbPath += File.separator + DATABASE_NAME;
        }

        rm = new RecordManager(dbPath);

        if (rm.getManagedTrees().contains(DATA_TREE)) {
            database = rm.getManagedTree(DATA_TREE);
        } else {
            PersistedBTreeConfiguration<String, KrbIdentity> config = new PersistedBTreeConfiguration<String, KrbIdentity>();
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
    public List<String> getIdentities(int start, int limit) {
        
        List<String> keys = new ArrayList<String>();
        
        KeyCursor<String> cursor = null;
        
        try {
            cursor = database.browseKeys();
            while(cursor.hasNext()) {
                keys.add(cursor.next());
            }
        }
        catch(Exception e) {
            LOG.debug("Errors occurred while fetching the principals", e);
        }
        finally {
            if(cursor != null) {
                cursor.close();
            }
        }
        
        return keys;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doGetIdentity(String principalName) {
        
        try {
            return database.get(principalName);
        }
        catch(KeyNotFoundException e) {
            LOG.debug("Identity {} doesn't exist", principalName);
        }
        catch(IOException e) {
            LOG.warn("Failed to get the identity {}", principalName);
            throw new RuntimeException(e);
        }
        
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected synchronized KrbIdentity doAddIdentity(KrbIdentity identity) {
        
        String p = identity.getPrincipalName();
        try {
            if(database.hasKey(p)) {
                LOG.debug("Identity {} already exists", p);
                return null;
            }
            
            return database.insert(p, identity);
        }
        catch(KeyNotFoundException e) {
            LOG.debug("No such identity {} exists", p);
            LOG.debug("", e);
            return null;
        }
        catch(IOException e) {
            LOG.warn("Failed to add the identity {}", p);
            throw new RuntimeException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected synchronized KrbIdentity doUpdateIdentity(KrbIdentity identity) {
        
        String p = identity.getPrincipalName();
        try {
            if(!database.hasKey(p)) {
                LOG.debug("No identity found with the principal {}", p);
                return null;
            }
            
            database.delete(p);
            
            return database.insert(p, identity);
        }
        catch(Exception e) {
            LOG.warn("Failed to update the identity {}", p);
            throw new RuntimeException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doDeleteIdentity(String principalName) {

        try {
            Tuple<String, KrbIdentity> t = database.delete(principalName);
            if (t == null) {
                LOG.debug("Identity {} doesn't exist", principalName);
            }
        }
        catch(IOException e) {
            LOG.warn("Failed to delete the identity {}", principalName);
            throw new RuntimeException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void stop() {
        try {
            LOG.debug("Closing the database");
            rm.close();
        }
        catch(Exception e) {
            LOG.warn("Failed to close the database", e);
        }
    }
}
