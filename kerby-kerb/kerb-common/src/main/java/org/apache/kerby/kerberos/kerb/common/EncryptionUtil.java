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
package org.apache.kerby.kerberos.kerb.common;

import org.apache.kerby.asn1.type.Asn1Encodeable;
import org.apache.kerby.asn1.type.Asn1Type;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.EncTypeHandler;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class EncryptionUtil {

    /**
     * an order preserved map containing cipher names to the corresponding algorithm
     * names in the descending order of strength
     */
    private static final Map<String, String> CIPHER_ALGO_MAP = new LinkedHashMap<>();

    static {
        CIPHER_ALGO_MAP.put("rc4", "ArcFourHmac");
        CIPHER_ALGO_MAP.put("arcfour", "ArcFourHmac");
        CIPHER_ALGO_MAP.put("aes256", "AES256");
        CIPHER_ALGO_MAP.put("aes128", "AES128");
        CIPHER_ALGO_MAP.put("des3", "DESede");
        CIPHER_ALGO_MAP.put("des", "DES");
    }

    public static String getAlgoNameFromEncType(EncryptionType encType) {

        String cipherName = encType.getName().toLowerCase();

        for (Map.Entry<String, String> entry : CIPHER_ALGO_MAP.entrySet()) {
            if (cipherName.startsWith(entry.getKey())) {
                return entry.getValue();
            }
        }

        throw new IllegalArgumentException("Unknown algorithm name for the encryption type "
                + encType);
    }

    /**
     * Order a list of EncryptionType in a decreasing strength order
     *
     * @param etypes The ETypes to order
     * @return A list of ordered ETypes. The strongest is on the left.
     */
    public static List<EncryptionType> orderEtypesByStrength(List<EncryptionType> etypes) {
        List<EncryptionType> ordered = new ArrayList<>(etypes.size());

        for (String algo : CIPHER_ALGO_MAP.values()) {
            for (EncryptionType encType : etypes) {
                String foundAlgo = getAlgoNameFromEncType(encType);

                if (algo.equals(foundAlgo)) {
                    ordered.add(encType);
                }
            }
        }

        return ordered;
    }

    public static List<EncryptionKey> generateKeys(
            List<EncryptionType> encryptionTypes) throws KrbException {
        List<EncryptionKey> results =
                new ArrayList<>(encryptionTypes.size());
        for (EncryptionType eType : encryptionTypes) {
            EncryptionKey encKey = EncryptionHandler.random2Key(eType);
            encKey.setKvno(1);
            results.add(encKey);
        }

        return results;
    }

    public static List<EncryptionKey> generateKeys(
            String principal, String passwd,
            List<EncryptionType> encryptionTypes) throws KrbException {
        List<EncryptionKey> results = new ArrayList<>(encryptionTypes.size());
        for (EncryptionType eType : encryptionTypes) {
            EncryptionKey encKey = EncryptionHandler.string2Key(
                principal, passwd, eType);
            encKey.setKvno(1);
            results.add(encKey);
        }

        return results;
    }

    public static EncryptionType getBestEncryptionType(List<EncryptionType> requestedTypes,
                                                       List<EncryptionType> configuredTypes) {
        for (EncryptionType configuredType : configuredTypes) {
            if (requestedTypes.contains(configuredType)) {
                return configuredType;
            }
        }

        // Maybe we have a different encryption name configured for the same type
        for (EncryptionType configuredType : configuredTypes) {
            int configuredTypeValue = configuredType.getValue();
            for (EncryptionType requestedType : requestedTypes) {
                if (configuredTypeValue == requestedType.getValue()) {
                    return requestedType;
                }
            }
        }

        return null;
    }

    public static EncryptedData seal(Asn1Encodeable asn1Type,
                                     EncryptionKey key, KeyUsage usage) throws KrbException {
        byte[] encoded = KrbCodec.encode(asn1Type);
        return EncryptionHandler.encrypt(encoded, key, usage);
    }

    public static <T extends Asn1Type> T unseal(EncryptedData encrypted, EncryptionKey key,
                                          KeyUsage usage, Class<T> krbType) throws KrbException {
        byte[] encoded = EncryptionHandler.decrypt(encrypted, key, usage);
        return KrbCodec.decode(encoded, krbType);
    }

    public static byte[] encrypt(EncryptionKey key,
          byte[] plaintext, KeyUsage usage) throws KrbException {
        EncTypeHandler encType = EncryptionHandler.getEncHandler(key.getKeyType());
        return encType.encrypt(plaintext, key.getKeyData(), usage.getValue());
    }

    public static byte[] decrypt(EncryptionKey key,
           byte[] cipherData, KeyUsage usage) throws KrbException {
        EncTypeHandler encType = EncryptionHandler.getEncHandler(key.getKeyType());
        return encType.decrypt(cipherData, key.getKeyData(), usage.getValue());
    }
}
