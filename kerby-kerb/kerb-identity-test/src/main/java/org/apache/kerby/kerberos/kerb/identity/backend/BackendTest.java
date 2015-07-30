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
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import static org.apache.kerby.kerberos.kerb.identity.backend.BackendTestUtil.TEST_PRINCIPAL;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * A common backend test utility
 */
public abstract class BackendTest {

    protected void testGet(IdentityBackend backend) throws KrbException {
        KrbIdentity kid = BackendTestUtil.createOneIdentity(TEST_PRINCIPAL);
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

    protected void testStore(IdentityBackend backend) throws KrbException {
        KrbIdentity kid = BackendTestUtil.createOneIdentity(TEST_PRINCIPAL);
        backend.addIdentity(kid);
        // clear the identity cache.
        backend.release();
        KrbIdentity kid2 = backend.getIdentity(TEST_PRINCIPAL);

        assertThat(kid).isEqualTo(kid2);

        //tearDown
        backend.deleteIdentity(TEST_PRINCIPAL);
    }

    protected void testUpdate(IdentityBackend backend) throws KrbException {
        KrbIdentity kid = BackendTestUtil.createOneIdentity(TEST_PRINCIPAL);
        backend.addIdentity(kid);

        kid.setDisabled(true);
        backend.updateIdentity(kid);

        // clear the identity cache.
        backend.release();
        assertThat(backend.getIdentity(TEST_PRINCIPAL)).isEqualTo(kid);

        //tearDown
        backend.deleteIdentity(TEST_PRINCIPAL);
    }

    protected void testDelete(IdentityBackend backend) throws KrbException {
        KrbIdentity kid = BackendTestUtil.createOneIdentity(TEST_PRINCIPAL);
        backend.addIdentity(kid);
        // clear the identity cache.
        backend.release();

        assertThat(backend.getIdentity(TEST_PRINCIPAL)).isNotNull();

        backend.deleteIdentity(TEST_PRINCIPAL);
        assertThat(backend.getIdentity(TEST_PRINCIPAL)).isNull();
    }

    protected void testGetIdentities(IdentityBackend backend) throws KrbException {
        KrbIdentity[] identities = BackendTestUtil.createManyIdentities();

        for (KrbIdentity identity : identities) {
            backend.addIdentity(identity);
        }

        // clear the identity cache.
        backend.release();

        Iterable<String> principals = backend.getIdentities();
        Iterator<String> iterator = principals.iterator();
        List<String> principalList = new LinkedList<>();
        while (iterator.hasNext()) {
            principalList.add(iterator.next());
        }
        assertThat(principalList).hasSize(identities.length)
                .contains(identities[0].getPrincipalName())
                .contains(identities[1].getPrincipalName())
                .contains(identities[2].getPrincipalName())
                .contains(identities[3].getPrincipalName())
                .contains(identities[4].getPrincipalName());

        //tearDown
        for (KrbIdentity identity : identities) {
            backend.deleteIdentity(identity.getPrincipalName());
        }
    }

    protected void cleanIdentities(IdentityBackend backend) throws KrbException {
        Iterable<String> identities = backend.getIdentities();
        Iterator<String> iterator = identities.iterator();
        while (iterator.hasNext()) {
            backend.deleteIdentity(iterator.next());
        }
    }
}
