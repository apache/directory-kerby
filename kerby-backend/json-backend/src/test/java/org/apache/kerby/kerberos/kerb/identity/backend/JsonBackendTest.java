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
import org.apache.kerby.kerberos.kerb.KrbException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import java.io.File;

/**
 * Json backend test
 */
public class JsonBackendTest extends BackendTestBase {
    private static File jsonBackendFile;

    @BeforeAll
    public static void setup() throws KrbException {
        File testDir = new File(System.getProperty("test.dir", "target"));
        jsonBackendFile = new File(testDir, "json-identity-backend-file");
        String jsonBackendFileString = jsonBackendFile.getAbsolutePath();

        Config backendConfig = new Conf();
        backendConfig.setString(JsonIdentityBackend.JSON_IDENTITY_BACKEND_DIR,
                jsonBackendFileString);
        backend = new JsonIdentityBackend(backendConfig);
        backend.initialize();
    }

    @AfterAll
    public static void cleanJsonBackendFile() {
        if (jsonBackendFile.exists()) {
            jsonBackendFile.delete();
        }
    }
}
