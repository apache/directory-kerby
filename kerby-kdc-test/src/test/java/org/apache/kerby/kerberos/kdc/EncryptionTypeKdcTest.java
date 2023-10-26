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
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbConfigKey;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;

import java.io.File;

public class EncryptionTypeKdcTest extends KerbyKdcTest {

    private static File jsonBackendFile;

    @Override
    protected void configKdcSeverAndClient() {
        super.configKdcSeverAndClient();
        KrbConfig krbConfig = getKrbClient().getKrbConfig();
        krbConfig.setBoolean(KrbConfigKey.PREAUTH_REQUIRED, false);
        krbConfig.setString(KrbConfigKey.PERMITTED_ENCTYPES,
                "es256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 des-cbc-crc des-cbc-md5 des3-cbc-sha1");
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
        backendConfig.setString(KdcConfigKey.KDC_IDENTITY_BACKEND,
            "org.apache.kerby.kerberos.kdc.identitybackend.JsonIdentityBackend");
    }

    @Test
    public void testKdc() throws Exception {
        performKdcTest();
    }

    @AfterAll
    public static void rmJsonBackendFile() {
        if (jsonBackendFile.exists()) {
            jsonBackendFile.delete();
        }
    }
}
