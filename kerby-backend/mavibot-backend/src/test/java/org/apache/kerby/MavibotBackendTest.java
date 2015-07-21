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


import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendTestBase;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendTestUtil;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Tests for MavibotBackend.
 *
 * @author <a href="mailto:kerby@directory.apache.org">Apache Kerby Project</a>
 */
public class MavibotBackendTest extends BackendTestBase {
    private static TemporaryFolder tmpFolder = new TemporaryFolder();

    @BeforeClass
    public static void setup() throws Exception {
        tmpFolder.create();
        
        File dbFile = tmpFolder.newFile();
        backend = new MavibotBackend(dbFile);
        backend.initialize();
    }
    
    @AfterClass
    public static void tearDown() throws KrbException {
        tmpFolder.delete();
    }

    // overriding this cause MavibotBackend doesn't support range search
    @Override
    protected void testGetIdentities(IdentityBackend backend) throws KrbException {
        KrbIdentity[] identities = BackendTestUtil.createManyIdentities();

        for (KrbIdentity identity : identities) {
            backend.addIdentity(identity);
        }

        // clear the identity cache.
        backend.release();

        List<String> principals = new LinkedList<>();
        Iterator<String> iterator = backend.getIdentities().iterator();
        while (iterator.hasNext()) {
            principals.add(iterator.next());
        }
        assertThat(principals).hasSize(identities.length);
        
        for (KrbIdentity entry : identities) {
            assertTrue(principals.contains(entry.getPrincipalName()));
        }
        
        for (KrbIdentity identity : identities) {
            backend.deleteIdentity(identity.getPrincipalName());
        }
    }
}
