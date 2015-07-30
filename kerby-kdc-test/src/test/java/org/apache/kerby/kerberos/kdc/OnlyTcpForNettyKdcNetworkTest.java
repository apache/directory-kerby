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
package org.apache.kerby.kerberos.kdc;

import org.apache.kerby.kerberos.kdc.identitybackend.JsonIdentityBackend;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.junit.AfterClass;
import org.junit.Test;

import java.io.File;

public class OnlyTcpForNettyKdcNetworkTest extends KerbyKdcTest {
    private static File jsonBackendFile;

    @AfterClass
    public static void rmJsonBackendFile() {
        if (jsonBackendFile.exists()) {
            jsonBackendFile.delete();
        }
    }

    @Override
    protected boolean allowTcp() {
        return true;
    }

    @Override
    protected boolean allowUdp() {
        return false;
    }

    @Override
    protected void prepareKdc() throws KrbException {
        super.prepareKdc();

        File testDir = new File(System.getProperty("test.dir", "target"));
        jsonBackendFile = new File(testDir, "json-backend-file");
        String jsonBackendFileString = jsonBackendFile.getAbsolutePath();

        BackendConfig backendConfig = getKdcServer().getBackendConfig();
        backendConfig.setString(
                JsonIdentityBackend.JSON_IDENTITY_BACKEND_DIR, jsonBackendFileString);
    }

    @Test
    public void testKdc() throws Exception {
        performKdcTest();
    }

}
