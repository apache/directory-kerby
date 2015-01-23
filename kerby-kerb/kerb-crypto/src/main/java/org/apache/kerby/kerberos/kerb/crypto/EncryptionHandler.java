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
package org.apache.kerby.kerberos.kerb.crypto;

import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.crypto.enc.*;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.common.*;

public class EncryptionHandler {

    public static EncryptionType getEncryptionType(String eType) throws KrbException {
        EncryptionType result = EncryptionType.fromName(eType);
        return result;
    }

    public static EncTypeHandler getEncHandler(String eType) throws KrbException {
        EncryptionType result = EncryptionType.fromName(eType);
        return getEncHandler(result);
    }

    public static EncTypeHandler getEncHandler(int eType) throws KrbException {
        EncryptionType eTypeEnum = EncryptionType.fromValue(eType);
        return getEncHandler(eTypeEnum);
    }

    public static EncTypeHandler getEncHandler(EncryptionType eType) throws KrbException {
        return getEncHandler(eType, false);
    }

    private static EncTypeHandler getEncHandler(EncryptionType eType, boolean check) throws KrbException {
        EncTypeHandler encHandler = null;

        switch (eType) {
            case DES_CBC_CRC:
                encHandler = new DesCbcCrcEnc();
                break;

            case DES_CBC_MD5:
            case DES:
                encHandler = new DesCbcMd5Enc();
                break;

            case DES_CBC_MD4:
                encHandler = new DesCbcMd4Enc();
                break;

            case DES3_CBC_SHA1:
            case DES3_CBC_SHA1_KD:
            case DES3_HMAC_SHA1:
                encHandler = new Des3CbcSha1Enc();
                break;

            case AES128_CTS_HMAC_SHA1_96:
            case AES128_CTS:
                encHandler = new Aes128CtsHmacSha1Enc();
                break;

            case AES256_CTS_HMAC_SHA1_96:
            case AES256_CTS:
                encHandler = new Aes256CtsHmacSha1Enc();
                break;

            case CAMELLIA128_CTS_CMAC:
            case CAMELLIA128_CTS:
                encHandler = new Camellia128CtsCmacEnc();
                break;

            case CAMELLIA256_CTS_CMAC:
            case CAMELLIA256_CTS:
                encHandler = new Camellia256CtsCmacEnc();
                break;

            case RC4_HMAC:
            case ARCFOUR_HMAC:
            case ARCFOUR_HMAC_MD5:
                encHandler = new Rc4HmacEnc();
                break;

            case RC4_HMAC_EXP:
            case ARCFOUR_HMAC_EXP:
            case ARCFOUR_HMAC_MD5_EXP:
                encHandler = new Rc4HmacExpEnc();
                break;

            case NONE:
            default:
                break;
        }

        if (encHandler == null && ! check) {
            String message = "Unsupported encryption type: " + eType.name();
            throw new KrbException(KrbErrorCode.KDC_ERR_ETYPE_NOSUPP, message);
        }

        return encHandler;
    }

    public static EncryptedData encrypt(byte[] plainText, EncryptionKey key, KeyUsage usage) throws KrbException {
        EncTypeHandler handler = getEncHandler(key.getKeyType());
        byte[] cipher = handler.encrypt(plainText, key.getKeyData(), usage.getValue());

        EncryptedData ed = new EncryptedData();
        ed.setCipher(cipher);
        ed.setEType(key.getKeyType());
        ed.setKvno(key.getKvno());

        return ed;
    }

    public static byte[] decrypt(byte[] data, EncryptionKey key, KeyUsage usage) throws KrbException {
        EncTypeHandler handler = getEncHandler(key.getKeyType());

        byte[] plainData = handler.decrypt(data, key.getKeyData(), usage.getValue());
        return plainData;
    }

    public static byte[] decrypt(EncryptedData data, EncryptionKey key, KeyUsage usage) throws KrbException {
        EncTypeHandler handler = getEncHandler(key.getKeyType());

        byte[] plainData = handler.decrypt(data.getCipher(), key.getKeyData(), usage.getValue());
        return plainData;
    }

    public static boolean isImplemented(EncryptionType eType) {
        EncTypeHandler handler = null;
        try {
            handler = getEncHandler(eType, true);
        } catch (KrbException e) {
            return false;
        }
        return  handler != null;
    }

    public static EncryptionKey string2Key(String principalName,
          String passPhrase, EncryptionType eType) throws KrbException {
        PrincipalName principal = new PrincipalName(principalName);
        return string2Key(passPhrase,
                PrincipalName.makeSalt(principal), null, eType);
    }

    public static EncryptionKey string2Key(String string, String salt,
                   byte[] s2kparams, EncryptionType eType) throws KrbException {
        EncTypeHandler handler = getEncHandler(eType);
        byte[] keyBytes = handler.str2key(string, salt, s2kparams);
        return new EncryptionKey(eType, keyBytes);
    }

    public static EncryptionKey random2Key(EncryptionType eType) throws KrbException {
        EncTypeHandler handler = getEncHandler(eType);

        byte[] randomBytes = Random.makeBytes(handler.keyInputSize());
        byte[] keyBytes = handler.random2Key(randomBytes);
        EncryptionKey encKey = new EncryptionKey(eType, keyBytes);
        return encKey;
    }
}
