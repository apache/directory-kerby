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
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A common backend test utility
 */
public abstract class BackendTest {

    static final String TEST_PRINCIPAL = "test@EXAMPLE.COM";

    static final EncryptionType[] ENC_TYPES = new EncryptionType[]{
            EncryptionType.AES128_CTS,
            EncryptionType.DES3_CBC_SHA1_KD
    };

    /**
     * A convenient method to run all tests on the given backend 
     * @param backend an instance of the backend to be tested
     */
    public void testAll(IdentityBackend backend) {
        testStore(backend);
        testGet(backend);
        testUpdate(backend);
        testDelete(backend);
        testGetIdentities(backend);
    }
    
    protected void testGet(IdentityBackend backend) {
        KrbIdentity kid = createOneIdentity(TEST_PRINCIPAL);
        backend.addIdentity(kid);
        // clear the identity cache.
        backend.release();

        KrbIdentity identity = backend.getIdentity(TEST_PRINCIPAL);
        assertThat(identity).isNotNull();
        assertThat(identity.getExpireTime()).isEqualTo(kid.getExpireTime());
        assertThat(identity.isDisabled()).isEqualTo(kid.isDisabled());
        assertThat(identity.getKeyVersion()).isEqualTo(kid.getKeyVersion());
        for (EncryptionKey expectedKey : kid.getKeys().values()) {
            EncryptionType actualType = EncryptionType.fromValue(expectedKey.getKeyType().getValue());
            EncryptionKey actualKey = identity.getKey(actualType);
            assertThat(actualKey.getKeyType().getValue()).isEqualTo(expectedKey.getKeyType().getValue());
            assertThat(actualKey.getKeyData()).isEqualTo(expectedKey.getKeyData());
            assertThat(actualKey.getKvno()).isEqualTo(expectedKey.getKvno());
        }

        //tearDown
        backend.deleteIdentity(TEST_PRINCIPAL);
    }

    protected void testStore(IdentityBackend backend) {
        KrbIdentity kid = createOneIdentity(TEST_PRINCIPAL);
        backend.addIdentity(kid);
        // clear the identity cache.
        backend.release();
        KrbIdentity kid2 = backend.getIdentity(TEST_PRINCIPAL);

        assertThat(kid).isEqualTo(kid2);

        //tearDown
        backend.deleteIdentity(TEST_PRINCIPAL);
    }

    protected void testUpdate(IdentityBackend backend) {
        KrbIdentity kid = createOneIdentity(TEST_PRINCIPAL);
        backend.addIdentity(kid);

        kid.setDisabled(true);
        backend.updateIdentity(kid);

        // clear the identity cache.
        backend.release();
        assertThat(backend.getIdentity(TEST_PRINCIPAL)).isEqualTo(kid);

        //tearDown
        backend.deleteIdentity(TEST_PRINCIPAL);
    }

    protected void testDelete(IdentityBackend backend) {
        KrbIdentity kid = createOneIdentity(TEST_PRINCIPAL);
        backend.addIdentity(kid);
        // clear the identity cache.
        backend.release();

        assertThat(backend.getIdentity(TEST_PRINCIPAL)).isNotNull();

        backend.deleteIdentity(TEST_PRINCIPAL);
        assertThat(backend.getIdentity(TEST_PRINCIPAL)).isNull();
    }

    protected void testGetIdentities(IdentityBackend backend) {
        KrbIdentity[] identities = createManyIdentities();

        for (KrbIdentity identity : identities) {
            backend.addIdentity(identity);
        }

        // clear the identity cache.
        backend.release();

        List<String> principals = backend.getIdentities(2, 3);
        assertThat(principals).hasSize(3)
                .contains(identities[2].getPrincipalName())
                .contains(identities[3].getPrincipalName())
                .contains(identities[4].getPrincipalName());

        //tearDown
        for (KrbIdentity identity : identities) {
            backend.deleteIdentity(identity.getPrincipalName());
        }
    }

    protected KrbIdentity[] createManyIdentities() {
        return new KrbIdentity[] {
                createOneIdentity("test1@EXAMPLE.COM"),
                createOneIdentity("test2@EXAMPLE.COM"),
                createOneIdentity("test3@EXAMPLE.COM"),
                createOneIdentity("test4@EXAMPLE.COM"),
                createOneIdentity("test5@EXAMPLE.COM"),
                createOneIdentity("test6@EXAMPLE.COM"),
        };
    }
    protected KrbIdentity createOneIdentity(String principal) {
        KrbIdentity kid = new KrbIdentity(principal);
        kid.setCreatedTime(KerberosTime.now());
        kid.setExpireTime(new KerberosTime(253402300799900L));
        kid.setDisabled(false);
        kid.setKeyVersion(1);
        kid.setLocked(false);
        kid.addKeys(generateKeys(kid.getPrincipalName()));

        return kid;
    }

    protected List<EncryptionKey> generateKeys(String principal) {
        String passwd = UUID.randomUUID().toString();
        try {
            return EncryptionUtil.generateKeys(principal, passwd, getEncryptionTypes());
        } catch (KrbException e) {
            throw new RuntimeException("Failed to create keys", e);
        }
    }

    protected List<EncryptionType> getEncryptionTypes() {
        return Arrays.asList(ENC_TYPES);
    }

    protected void cleanIdentities(IdentityBackend backend) {
        List<String> identities = backend.getIdentities(0, -1);
        if (identities != null) {
            for (String identity : identities) {
                backend.deleteIdentity(identity);
            }
        }
    }
}
