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
package org.apache.kerby.kerberos.kerb.util;

import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.keytab.KeytabEntry;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import static org.assertj.core.api.Assertions.fail;

/*
The principal was created with password '123456'
KVNO Principal
---- --------------------------------------------------------------------------
   1 test@SH.INTEL.COM (des-cbc-crc)
   1 test@SH.INTEL.COM (des3-cbc-sha1)
   1 test@SH.INTEL.COM (des-hmac-sha1)
   1 test@SH.INTEL.COM (aes256-cts-hmac-sha1-96)
   1 test@SH.INTEL.COM (aes128-cts-hmac-sha1-96)
   1 test@SH.INTEL.COM (arcfour-hmac)
   1 test@SH.INTEL.COM (camellia256-cts-cmac)
   1 test@SH.INTEL.COM (camellia128-cts-cmac)
 */
public class KeysTest {
    private static final String TEST_PASSWORD = "123456";

    private Keytab keytab;

    @BeforeEach
    public void setUp() throws IOException {
        try (InputStream kis = KeysTest.class.getResourceAsStream("/test.keytab")) {
            keytab = Keytab.loadKeytab(kis);
        }
    }

    @Test
    public void testString2Key() throws KrbException {
        List<PrincipalName> principals = keytab.getPrincipals();
        PrincipalName principal = principals.get(0);
        List<KeytabEntry> entries = keytab.getKeytabEntries(principal);

        for (KeytabEntry ke : entries) {
            EncryptionType keyType = ke.getKey().getKeyType();
            if (keyType.usesAES256()) {
                continue;
            }
            if (EncryptionHandler.isImplemented(keyType)) {
                EncryptionKey genKey = EncryptionHandler.string2Key(principal.getName(),
                        TEST_PASSWORD, keyType);
                if (!ke.getKey().equals(genKey)) {
                    fail("str2key failed for key type: " + keyType.getName());
                    //System.err.println("str2key failed for key type: " + keyType.getName());
                }
            }
        }
    }
}
