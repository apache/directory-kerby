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

import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.keytab.KeytabEntry;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

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
public class KeytabTest {

    private Keytab keytab;

    @Before
    public void setUp() throws IOException {
        InputStream kis = KeytabTest.class.getResourceAsStream("/test.keytab");
        keytab = new Keytab();
        keytab.load(kis);
    }

    @Test
    public void testKeytab() {
        Assert.assertNotNull(keytab);

        List<PrincipalName> principals = keytab.getPrincipals();
        PrincipalName principal = principals.get(0);
        List<KeytabEntry> entries = keytab.getKeytabEntries(principal);
        for (KeytabEntry ke : entries) {
            Assert.assertTrue(ke.getKvno() == 1);
        }
    }

    public static void main(String[] args) throws IOException {
        InputStream kis = KeytabTest.class.getResourceAsStream("test.keytab");
        Keytab keytab = new Keytab();
        keytab.load(kis);
        System.out.println("Principals:" + keytab.getPrincipals().size());
    }
}
