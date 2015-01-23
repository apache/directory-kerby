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
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.cksum.*;
import org.apache.kerby.kerberos.kerb.spec.common.CheckSum;
import org.apache.kerby.kerberos.kerb.spec.common.CheckSumType;
import org.apache.kerby.kerberos.kerb.spec.common.KeyUsage;

public class CheckSumHandler {

    public static CheckSumTypeHandler getCheckSumHandler(String cksumType) throws KrbException {
        CheckSumType eTypeEnum = CheckSumType.fromName(cksumType);
        return getCheckSumHandler(eTypeEnum);
    }

    public static CheckSumTypeHandler getCheckSumHandler(int cksumType) throws KrbException {
        CheckSumType eTypeEnum = CheckSumType.fromValue(cksumType);
        return getCheckSumHandler(eTypeEnum);
    }

    public static boolean isImplemented(CheckSumType cksumType) throws KrbException {
        return getCheckSumHandler(cksumType, true) != null;
    }

    public static CheckSumTypeHandler getCheckSumHandler(CheckSumType cksumType) throws KrbException {
        return getCheckSumHandler(cksumType, false);
    }

    private static CheckSumTypeHandler getCheckSumHandler(CheckSumType cksumType, boolean check) throws KrbException {
        CheckSumTypeHandler cksumHandler = null;
        switch (cksumType) {
            case CRC32:
                cksumHandler = new Crc32CheckSum();
                break;

            case DES_MAC:
                cksumHandler = new DesCbcCheckSum();
                break;

            case RSA_MD4:
                cksumHandler = new RsaMd4CheckSum();
                break;

            case RSA_MD5:
                cksumHandler = new RsaMd5CheckSum();
                break;

            case NIST_SHA:
                cksumHandler = new Sha1CheckSum();
                break;

            case RSA_MD4_DES:
                cksumHandler = new RsaMd4DesCheckSum();
                break;

            case RSA_MD5_DES:
                cksumHandler = new RsaMd5DesCheckSum();
                break;

            case HMAC_SHA1_DES3:
            case HMAC_SHA1_DES3_KD:
                cksumHandler = new HmacSha1Des3CheckSum();
                break;

            case HMAC_SHA1_96_AES128:
                cksumHandler = new HmacSha1Aes128CheckSum();
                break;

            case HMAC_SHA1_96_AES256:
                cksumHandler = new HmacSha1Aes256CheckSum();
                break;

            case CMAC_CAMELLIA128:
                cksumHandler = new CmacCamellia128CheckSum();
                break;

            case CMAC_CAMELLIA256:
                cksumHandler = new CmacCamellia256CheckSum();
                break;

            case HMAC_MD5_ARCFOUR:
                cksumHandler = new HmacMd5Rc4CheckSum();
                break;

            case MD5_HMAC_ARCFOUR:
                cksumHandler = new Md5HmacRc4CheckSum();
                break;

            default:
                break;
        }

        if (cksumHandler == null && ! check) {
            String message = "Unsupported checksum type: " + cksumType.name();
            throw new KrbException(KrbErrorCode.KDC_ERR_SUMTYPE_NOSUPP, message);
        }

        return cksumHandler;
    }

    public static CheckSum checksum(CheckSumType checkSumType, byte[] bytes) throws KrbException {
        CheckSumTypeHandler handler = getCheckSumHandler(checkSumType);
        byte[] checksumBytes = handler.checksum(bytes);
        CheckSum checkSum = new CheckSum();
        checkSum.setCksumtype(checkSumType);
        checkSum.setChecksum(checksumBytes);
        return checkSum;
    }

    public static boolean verify(CheckSum checkSum, byte[] bytes) throws KrbException {
        CheckSumType checkSumType = checkSum.getCksumtype();
        CheckSumTypeHandler handler = getCheckSumHandler(checkSumType);
        return handler.verify(bytes, checkSum.getChecksum());
    }

    public static CheckSum checksumWithKey(CheckSumType checkSumType,
                           byte[] bytes, byte[] key, KeyUsage usage) throws KrbException {
        CheckSumTypeHandler handler = getCheckSumHandler(checkSumType);
        byte[] checksumBytes = handler.checksumWithKey(bytes, key, usage.getValue());
        CheckSum checkSum = new CheckSum();
        checkSum.setCksumtype(checkSumType);
        checkSum.setChecksum(checksumBytes);
        return checkSum;
    }

    public static boolean verifyWithKey(CheckSum checkSum, byte[] bytes,
                                        byte[] key, KeyUsage usage) throws KrbException {
        CheckSumType checkSumType = checkSum.getCksumtype();
        CheckSumTypeHandler handler = getCheckSumHandler(checkSumType);
        return handler.verifyWithKey(bytes, key,
                usage.getValue(), checkSum.getChecksum());
    }
}
