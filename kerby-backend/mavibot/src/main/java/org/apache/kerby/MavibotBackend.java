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

import java.io.File;
import java.util.List;

import org.apache.directory.mavibot.btree.BTree;
import org.apache.directory.mavibot.btree.BTreeFactory;
import org.apache.directory.mavibot.btree.BTreeTypeEnum;
import org.apache.directory.mavibot.btree.PersistedBTreeConfiguration;
import org.apache.directory.mavibot.btree.RecordManager;
import org.apache.directory.mavibot.btree.serializer.StringSerializer;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.AbstractIdentityBackend;

/**
 * A backend based on Apache Mavibot(an MVCC BTree library).
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class MavibotBackend extends AbstractIdentityBackend {
    /** the RecordManager of Mavibot */
    private RecordManager rm;

    /** the BTree holding all data */
    private BTree<String, KrbIdentity> database;

    /** name of the database */
    private static final String DATA_TREE = "kerby-data";

    /** name of the database file */
    private static final String DATABASE_NAME = "kerby-data.db";

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
	return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getIdentities() {
	return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doGetIdentity(String principalName) {
	return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) {
	return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) {
	return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doDeleteIdentity(String principalName) {

    }
}
