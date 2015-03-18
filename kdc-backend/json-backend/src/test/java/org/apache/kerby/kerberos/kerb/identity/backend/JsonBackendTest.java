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

import org.apache.kerby.config.Conf;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kdc.identitybackend.JsonIdentityBackend;
import org.junit.Before;
import org.junit.Test;

import java.io.File;

/**
 * Json backend test
 */
public class JsonBackendTest extends BackendTest {
    private IdentityBackend backend;

    @Before
    public void setup() {
        File testDir = new File(System.getProperty("test.dir", "target"));
        String jsonBackendFileString = new File(testDir, "json-identity-backend-file").getAbsolutePath();

        Config backendConfig = new Conf();
        backendConfig.setString(JsonIdentityBackend.JSON_IDENTITY_BACKEND_FILE, jsonBackendFileString);

        backend = new JsonIdentityBackend(backendConfig);
        backend.initialize();
    }

    @Test
    public void testGet() {
        super.testGet(backend);
    }

    @Test
    public void testStore() {
        super.testStore(backend);
    }

    @Test
    public void testUpdate() {
        super.testUpdate(backend);
    }

    @Test
    public void testDelete() {
        super.testDelete(backend);
    }

    @Test
    public void testGetIdentities() {
        super.testGetIdentities(backend);
    }

}
