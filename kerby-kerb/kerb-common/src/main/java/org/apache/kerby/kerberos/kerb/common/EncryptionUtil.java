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

import org.apache.kerby.asn1.type.AbstractAsn1Type;
import org.apache.kerby.asn1.type.Asn1Type;
import org.apache.kerby.kerberos.kerb.codec.KrbCodec;
import org.apache.kerby.kerberos.kerb.crypto.EncTypeHandler;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptedData;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.common.KeyUsage;

import java.util.ArrayList;
import java.util.List;

public class EncryptionUtil {

    public static List<EncryptionKey> generateKeys(List<EncryptionType> encryptionTypes) throws KrbException {
        List<EncryptionKey> results = new ArrayList<EncryptionKey>(encryptionTypes.size());
        EncryptionKey encKey;
        for (EncryptionType eType : encryptionTypes) {
            encKey = EncryptionHandler.random2Key(eType);
            results.add(encKey);
        }

        return results;
    }

    public static List<EncryptionKey> generateKeys(String principal, String passwd,
                                                   List<EncryptionType> encryptionTypes) throws KrbException {
        List<EncryptionKey> results = new ArrayList<EncryptionKey>(encryptionTypes.size());
        EncryptionKey encKey;
        for (EncryptionType eType : encryptionTypes) {
            encKey = EncryptionHandler.string2Key(principal, passwd, eType);
            results.add(encKey);
        }

        return results;
    }

    public static EncryptionType getBestEncryptionType(List<EncryptionType> requestedTypes,
                                                       List<EncryptionType> configuredTypes) {
        for (EncryptionType encryptionType : configuredTypes) {
            if (requestedTypes.contains(encryptionType)) {
                return encryptionType;
            }
        }

        return null;
    }

    public static EncryptedData seal(AbstractAsn1Type asn1Type,
                                     EncryptionKey key, KeyUsage usage) throws KrbException {
        byte[] encoded = asn1Type.encode();
        EncryptedData encrypted = EncryptionHandler.encrypt(encoded, key, usage);
        return encrypted;
    }

    public static <T extends Asn1Type> T unseal(EncryptedData encrypted, EncryptionKey key,
                                          KeyUsage usage, Class<T> krbType) throws KrbException {
        byte[] encoded = EncryptionHandler.decrypt(encrypted, key, usage);
        return KrbCodec.decode(encoded, krbType);
    }

    public static byte[] encrypt(EncryptionKey key,
          byte[] plaintext, int usage) throws KrbException {
        EncTypeHandler encType = EncryptionHandler.getEncHandler(key.getKeyType());
        byte[] cipherData = encType.encrypt(plaintext, key.getKeyData(), usage);
        return cipherData;
    }

    public static byte[] decrypt(EncryptionKey key,
           byte[] cipherData, int usage) throws KrbException {
        EncTypeHandler encType = EncryptionHandler.getEncHandler(key.getKeyType());
        byte[] plainData = encType.decrypt(cipherData, key.getKeyData(), usage);
        return plainData;
    }
}
