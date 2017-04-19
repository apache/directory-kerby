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
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static org.assertj.core.api.Assertions.assertThat;

public class KeytabTest {
    @Test
    public void testKeytab() throws IOException  {
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
        InputStream kis = KeytabTest.class.getResourceAsStream("/test.keytab");
        Keytab keytab = Keytab.loadKeytab(kis);
        assertThat(keytab).isNotNull();

        List<PrincipalName> principals = keytab.getPrincipals();
        PrincipalName principal = principals.get(0);
        List<KeytabEntry> entries = keytab.getKeytabEntries(principal);
        for (KeytabEntry ke : entries) {
            assertThat(ke.getKvno() == 1).isTrue();
        }
        assertEquals(8, entries.size());
    }

    @Test
    public void testKeytabWithMultiplePrinciples() throws IOException {
/*
The principal was created with password 'test'

Keytab name: FILE:test.keytab
KVNO Timestamp         Principal
---- ----------------- --------------------------------------------------------
   3 04/11/17 14:16:34 test/examples.com@EXAMPLE.COM (aes256-cts-hmac-sha1-96)
   3 04/11/17 14:16:34 test/examples.com@EXAMPLE.COM (aes128-cts-hmac-sha1-96)
   3 04/11/17 14:16:34 test/examples.com@EXAMPLE.COM (des3-cbc-sha1)
   3 04/11/17 14:16:34 test/examples.com@EXAMPLE.COM (arcfour-hmac)
   3 04/11/17 14:16:34 test/examples.com@EXAMPLE.COM (camellia256-cts-cmac)
   3 04/11/17 14:16:34 test/examples.com@EXAMPLE.COM (camellia128-cts-cmac)
   3 04/11/17 14:16:34 test/examples.com@EXAMPLE.COM (des-hmac-sha1)
   3 04/11/17 14:16:34 test/examples.com@EXAMPLE.COM (des-cbc-md5)
   3 04/11/17 14:16:51 HTTP/examples.com@EXAMPLE.COM (aes256-cts-hmac-sha1-96)
   3 04/11/17 14:16:52 HTTP/examples.com@EXAMPLE.COM (aes128-cts-hmac-sha1-96)
   3 04/11/17 14:16:52 HTTP/examples.com@EXAMPLE.COM (des3-cbc-sha1)
   3 04/11/17 14:16:52 HTTP/examples.com@EXAMPLE.COM (arcfour-hmac)
   3 04/11/17 14:16:52 HTTP/examples.com@EXAMPLE.COM (camellia256-cts-cmac)
   3 04/11/17 14:16:52 HTTP/examples.com@EXAMPLE.COM (camellia128-cts-cmac)
   3 04/11/17 14:16:52 HTTP/examples.com@EXAMPLE.COM (des-hmac-sha1)
   3 04/11/17 14:16:52 HTTP/examples.com@EXAMPLE.COM (des-cbc-md5)
 */
        InputStream kis = KeytabTest.class.getResourceAsStream("/test_multiple_principles.keytab");
        Keytab keytab = Keytab.loadKeytab(kis);
        assertThat(keytab).isNotNull();

        List<PrincipalName> principals = keytab.getPrincipals();
        assertEquals(2, keytab.getPrincipals().size());

        int numEntries = keytab.getKeytabEntries(principals.get(0)).size()
                + keytab.getKeytabEntries(principals.get(1)).size();
        assertEquals(16, numEntries);
    }

    @Test
    public void testSKeytab() throws IOException {

        InputStream kis = KeytabTest.class.getResourceAsStream("/test_multiple_principles.keytab");

        Keytab keytab = Keytab.loadKeytab(kis);
        assertThat(keytab).isNotNull();

        List<PrincipalName> principals = keytab.getPrincipals();
        assertEquals(2, keytab.getPrincipals().size());

        int numEntries = keytab.getKeytabEntries(principals.get(0)).size()
                + keytab.getKeytabEntries(principals.get(1)).size();
        assertEquals(16, numEntries);
    }

    public static void main(String[] args) throws IOException {
        InputStream kis = KeytabTest.class.getResourceAsStream("test.keytab");
        Keytab keytab = Keytab.loadKeytab(kis);
        System.out.println("Principals:" + keytab.getPrincipals().size());
    }
}
