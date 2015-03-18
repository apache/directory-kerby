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
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A common backend test utility
 */
public abstract class BackendTest {

    static final String TEST_PRINCIPAL = "test@EXAMPLE.COM";

    static final EncryptionType[] encTypes = new EncryptionType[]{
            EncryptionType.AES128_CTS,
            EncryptionType.DES3_CBC_SHA1_KD
    };

    protected void testGet(IdentityBackend backend) {
        KrbIdentity kid = createOneIdentity(TEST_PRINCIPAL);
        backend.addIdentity(kid);

        assertThat(backend.getIdentity(TEST_PRINCIPAL)).isNotNull();

        //tearDown
        backend.deleteIdentity(TEST_PRINCIPAL);
    }

    protected void testStore(IdentityBackend backend) {
        KrbIdentity kid = createOneIdentity(TEST_PRINCIPAL);
        backend.addIdentity(kid);
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

        assertThat(backend.getIdentity(TEST_PRINCIPAL)).isEqualTo(kid);

        //tearDown
        backend.deleteIdentity(TEST_PRINCIPAL);
    }

    protected void testDelete(IdentityBackend backend) {
        KrbIdentity kid = createOneIdentity(TEST_PRINCIPAL);
        backend.addIdentity(kid);
        assertThat(backend.getIdentity(TEST_PRINCIPAL)).isNotNull();

        backend.deleteIdentity(TEST_PRINCIPAL);
        assertThat(backend.getIdentity(TEST_PRINCIPAL)).isNull();
    }

    protected void testGetIdentities(IdentityBackend backend) {
        KrbIdentity[] identities = createManyIdentities();

        for (KrbIdentity identity : identities) {
            backend.addIdentity(identity);
        }

        List<String> principals = backend.getIdentities(2, 5);
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
        kid.setExpireTime(KerberosTime.NEVER);
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
        return Arrays.asList(encTypes);
    }
}
