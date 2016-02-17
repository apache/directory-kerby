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
package org.apache.kerby.kerberos.kerb.identity.backend;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Json backend test
 */
public abstract class BackendTestBase extends BackendTest {
    protected static IdentityBackend backend;

    /**
     * Create and prepare an identity backend for the tests. Must override.
     * @throws Exception e
     */
    @BeforeClass
    public static void setup() throws Exception {
        backend = null;
    }

    @Test
    public void testGet() throws KrbException {
        super.testGet(backend);
    }

    @Test
    public void testStore() throws KrbException {
        super.testStore(backend);
    }

    @Test
    public void testUpdate() throws KrbException {
        testUpdate(backend);
    }

    @Test
    public void testDelete() throws KrbException {
        testDelete(backend);
    }

    @Test
    public void testGetIdentities() throws KrbException {
        testGetIdentities(backend);
    }

    @AfterClass
    public static void tearDown() throws KrbException {
        if (backend != null) {
            backend.stop();
            backend.release();
        }
    }
}
