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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A common backend test utility
 */
public final class BackendTestUtil {

    static final String TEST_PRINCIPAL_PREFIX = "test";
    static final String TEST_REALM = "EXAMPLE.COM";

    public static final String TEST_PRINCIPAL = TEST_PRINCIPAL_PREFIX + "@" + TEST_REALM;

    static final EncryptionType[] ENC_TYPES = new EncryptionType[]{
            EncryptionType.AES128_CTS,
            EncryptionType.DES3_CBC_SHA1_KD
    };

    public static void createManyIdentities(IdentityBackend backend,
                                            int count) throws KrbException {
        int howMany = count > 0 ? count : 20;
        List<KrbIdentity> identities = createManyIdentities(howMany);

        for (KrbIdentity identity : identities) {
            backend.addIdentity(identity);
        }
    }

    public static KrbIdentity[] createManyIdentities() throws KrbException {
        List<KrbIdentity> results = createManyIdentities(20);
        return results.toArray(new KrbIdentity[results.size()]);
    }

    public static List<KrbIdentity> createManyIdentities(
            int count) throws KrbException {
        List<KrbIdentity> results = new ArrayList<>(count);

        for (int i = 0; i < count; ++i) {
            String tmp = TEST_PRINCIPAL_PREFIX + i + "@" + TEST_REALM;
            results.add(createOneIdentity(tmp));
        }

        return results;
    }

    public static void createTheTestIdentity(
            IdentityBackend backend) throws KrbException {
        backend.addIdentity(createOneIdentity(TEST_PRINCIPAL));
    }

    public static void getTheTestIdentity(
            IdentityBackend backend) throws KrbException {
        KrbIdentity identity = backend.getIdentity(TEST_PRINCIPAL);
        if (identity == null) {
            throw new KrbException("Failed to get the test principal");
        }
    }

    public static KrbIdentity createOneIdentity() throws KrbException {
        return createOneIdentity(TEST_PRINCIPAL);
    }

    public static KrbIdentity createOneIdentity(String principal) throws KrbException {
        KrbIdentity kid = new KrbIdentity(principal);
        kid.setCreatedTime(KerberosTime.now());
        kid.setExpireTime(KerberosTime.now());
        kid.setDisabled(false);
        kid.setKeyVersion(1);
        kid.setLocked(false);
        kid.addKeys(generateKeys());

        return kid;
    }

    public static List<EncryptionKey> generateKeys() throws KrbException {
        return EncryptionUtil.generateKeys(getEncryptionTypes());
    }

    public static List<EncryptionType> getEncryptionTypes() {
        return Arrays.asList(ENC_TYPES);
    }
}
