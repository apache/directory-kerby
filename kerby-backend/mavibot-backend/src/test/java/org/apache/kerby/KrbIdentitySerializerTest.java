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

import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests for KrbIdentity serializer.
 *
 * @author <a href="mailto:kerby@directory.apache.org">Apache Kerby Project</a>
 */
public class KrbIdentitySerializerTest {

    private KrbIdentitySerializer serializer = KrbIdentitySerializer.INSTANCE;
    
    @Test
    public void testSerialization() throws Exception {
        KrbIdentity entry = new KrbIdentity("hnelson@EXAMPLE.COM");
        entry.setCreatedTime(new KerberosTime(System.currentTimeMillis()));
        entry.setDisabled(true);
        entry.setKeyVersion(1);
        entry.setLocked(true);

        byte[] junk = new byte[11];
        Arrays.fill(junk, (byte) 1);
        EncryptionKey key1 = new EncryptionKey(EncryptionType.AES128_CTS, junk);
        entry.addKey(key1);

        EncryptionKey key2 = new EncryptionKey(EncryptionType.AES128_CTS_HMAC_SHA1_96, junk);
        entry.addKey(key2);

        byte[] serialized = serializer.serialize(entry);
        
        KrbIdentity deserialized = serializer.fromBytes(serialized);
        verifyEquality(entry, deserialized);
        
        deserialized = serializer.fromBytes(serialized, 0);
        verifyEquality(entry, deserialized);
        
        deserialized = serializer.deserialize(ByteBuffer.wrap(serialized));
        verifyEquality(entry, deserialized);
        
        try {
            deserialized = serializer.fromBytes(serialized, 1);
            fail("shouldn't deserialize");
        } catch (Exception e) {
            // expected
            System.out.println(e);
        }
    }
    
    
    private void verifyEquality(KrbIdentity expected, KrbIdentity actual) {
        assertNotNull(actual);
        assertEquals(expected.getPrincipalName(), actual.getPrincipalName());
        assertEquals(expected.getCreatedTime().getTime(), actual.getCreatedTime().getTime());
        assertEquals(expected.getExpireTime().getTime(), actual.getExpireTime().getTime());
        assertEquals(expected.isDisabled(), actual.isDisabled());
        assertEquals(expected.isLocked(), actual.isLocked());
        assertEquals(expected.getKeyVersion(), actual.getKeyVersion());
        assertEquals(expected.getKdcFlags(), actual.getKdcFlags());
        assertEquals(expected.getKeys().size(), actual.getKeys().size());
        
        Map<EncryptionType, EncryptionKey> exKeys = expected.getKeys();
        Map<EncryptionType, EncryptionKey> acKeys = actual.getKeys();
        for (EncryptionType et : exKeys.keySet()) {
            EncryptionKey exKey = exKeys.get(et);
            EncryptionKey acKey = acKeys.get(et);
            
            assertEquals(exKey.getKvno(), acKey.getKvno());
            assertEquals(exKey.getKeyType(), acKey.getKeyType());
            boolean equal = Arrays.equals(exKey.getKeyData(), acKey.getKeyData());
            assertTrue(equal);
        }
    }
}
