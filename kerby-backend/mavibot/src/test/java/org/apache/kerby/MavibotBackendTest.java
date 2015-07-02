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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendTest;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Tests for MavibotBackend.
 *
 * @author <a href="mailto:kerby@directory.apache.org">Apache Kerby Project</a>
 */
public class MavibotBackendTest extends BackendTest {

    private MavibotBackend backend;
    
    private TemporaryFolder tmpFolder = new TemporaryFolder();
    
    @Before
    public void setup() throws Exception {
        tmpFolder.create();
        
        File dbFile = tmpFolder.newFile();
        backend = new MavibotBackend(dbFile);
        backend.initialize();
    }
    
    @After
    public void clean() {
        backend.stop();
        tmpFolder.delete();
    }
    
    @Test
    public void testBackend() {
        super.testAll(backend);
    }

    // overriding this cause MavibotBackend doesn't support range search
    public void testGetIdentities(IdentityBackend backend) {
        KrbIdentity[] identities = createManyIdentities();

        for (KrbIdentity identity : identities) {
            backend.addIdentity(identity);
        }

        // clear the identity cache.
        backend.release();

        List<String> principals = backend.getIdentities(0, 0);
        assertThat(principals).hasSize(identities.length);
        
        for(KrbIdentity entry : identities) {
            assertTrue(principals.contains(entry.getPrincipalName()));
        }
        
        for (KrbIdentity identity : identities) {
            backend.deleteIdentity(identity.getPrincipalName());
        }
    }
}
