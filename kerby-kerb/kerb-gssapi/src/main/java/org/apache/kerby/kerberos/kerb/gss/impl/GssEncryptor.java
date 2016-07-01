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
package org.apache.kerby.kerberos.kerb.gss.impl;


import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.CheckSumHandler;
import org.apache.kerby.kerberos.kerb.crypto.CheckSumTypeHandler;
import org.apache.kerby.kerberos.kerb.crypto.EncTypeHandler;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.crypto.cksum.provider.Md5Provider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.DesProvider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.Rc4Provider;
import org.apache.kerby.kerberos.kerb.type.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.ietf.jgss.GSSException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class implements encryption related function used in GSS tokens
 */
public class GssEncryptor {

    private final EncryptionKey encKey;
    private final EncryptionType encKeyType; // The following two variables used for convenience
    private final byte[] encKeyBytes;

    private CheckSumType checkSumTypeDef;
    private int checkSumSize;

    private boolean isV2 = false;
    private int sgnAlg = 0xFFFF;
    private int sealAlg = 0xFFFF;
    private boolean isArcFourHmac = false;

    private static final byte[] IV_ZEROR_8B = new byte[8];

    public GssEncryptor(EncryptionKey key) throws GSSException {
        encKey = key;
        encKeyBytes = encKey.getKeyData();
        encKeyType = key.getKeyType();

        if (encKeyType == EncryptionType.AES128_CTS_HMAC_SHA1_96) {
            checkSumSize = 12;
            checkSumTypeDef = CheckSumType.HMAC_SHA1_96_AES128;
            isV2 = true;
        } else if (encKeyType == EncryptionType.AES256_CTS_HMAC_SHA1_96) {
            checkSumSize = 12;
            checkSumTypeDef = CheckSumType.HMAC_SHA1_96_AES256;
            isV2 = true;
        } else if (encKeyType == EncryptionType.DES_CBC_CRC || encKeyType == EncryptionType.DES_CBC_MD5) {
            sgnAlg = GssTokenV1.SGN_ALG_DES_MAC_MD5;
            sealAlg = GssTokenV1.SEAL_ALG_DES;
            checkSumSize = 8;
        } else if (encKeyType == EncryptionType.DES3_CBC_SHA1) {
            sgnAlg = GssTokenV1.SGN_ALG_HMAC_SHA1_DES3_KD;
            sealAlg = GssTokenV1.SEAL_ALG_DES3_KD;
            checkSumSize = 20;
        } else if (encKeyType == EncryptionType.ARCFOUR_HMAC) {
            sgnAlg = GssTokenV1.SGN_ALG_RC4_HMAC;
            sealAlg = GssTokenV1.SEAL_ALG_RC4_HMAC;
            checkSumSize = 16;
            isArcFourHmac = true;
        } else {
            throw new GSSException(GSSException.FAILURE, -1,
                    "Invalid encryption type: " + encKeyType.getDisplayName());
        }
    }

    /**
     * Return true if it is encryption type defined in RFC 4121
     * @return
     */
    public boolean isV2() {
        return isV2;
    }

    public int getSgnAlg() {
        return sgnAlg;
    }

    public int getSealAlg() {
        return sealAlg;
    }

    public boolean isArcFourHmac() {
        return isArcFourHmac;
    }

    public byte[] encryptData(byte[] tokenHeader, byte[] data,
                              int offset, int len, int keyUsage) throws GSSException {
        byte[] ret;
        byte[] toProcess = new byte[tokenHeader.length + len];
        System.arraycopy(data, offset, toProcess, 0, len);
        System.arraycopy(tokenHeader, 0, toProcess, len, tokenHeader.length);

        ret = encryptData(toProcess, keyUsage);
        return ret;
    }

    public byte[] encryptData(byte[] toProcess, int keyUsage) throws GSSException {
        byte[] ret;
        try {
            EncTypeHandler encHandler = EncryptionHandler.getEncHandler(encKey.getKeyType());
            ret = encHandler.encrypt(toProcess, encKey.getKeyData(), keyUsage);
        } catch (KrbException e) {
            throw new GSSException(GSSException.FAILURE, -1, e.getMessage());
        }
        return ret;
    }

    public byte[] decryptData(byte[] dataEncrypted, int keyUsage) throws GSSException {
        byte[] ret;
        try {
            EncTypeHandler encHandler = EncryptionHandler.getEncHandler(encKey.getKeyType());
            ret = encHandler.decrypt(dataEncrypted, encKey.getKeyData(), keyUsage);
        } catch (KrbException e) {
            throw new GSSException(GSSException.FAILURE, -1, e.getMessage());
        }
        return ret;
    }

    public byte[] calculateCheckSum(byte[] header, byte[] data, int offset, int len, int keyUsage)
            throws GSSException {
        int totalLen = len + (header == null ? 0 : header.length);
        byte[] buffer = new byte[totalLen];
        System.arraycopy(data, offset, buffer, 0, len);
        if (header != null) {
            System.arraycopy(header, 0, buffer, len, header.length);
        }

        try {
            return CheckSumHandler.getCheckSumHandler(checkSumTypeDef)
                    .checksumWithKey(buffer, encKey.getKeyData(), keyUsage);
        } catch (KrbException e) {
            throw new GSSException(GSSException.FAILURE, -1,
                    "Exception in checksum calculation:" + e.getMessage());
        }
    }

    /**
     * Get the size of the corresponding checksum algorithm
     * @return
     * @throws GSSException
     */
    public int getCheckSumSize() throws GSSException {
        return checkSumSize;
    }


    private void addPadding(int paddingLen, byte[] outBuf, int offset) {
        for (int i = 0; i < paddingLen; i++) {
            outBuf[offset + i] = (byte) paddingLen;
        }
    }

    private byte[] getFirstBytes(byte[] src, int len) {
        if (len < src.length) {
            byte[] ret = new byte[len];
            System.arraycopy(src, 0, ret, 0, len);
            return ret;
        }
        return src;
    }

    private byte[] getKeyBytesWithLength(int len) {
        return getFirstBytes(encKeyBytes, len);
    }

    public byte[] calculateCheckSum(byte[] confounder, byte[] header,
                                    byte[] data, int offset, int len, int paddingLen, boolean isMic)
            throws GSSException {
        byte[] ret;
        int keyUsage = GssTokenV1.KG_USAGE_SIGN;
        CheckSumTypeHandler handler;

        int keySize;
        byte[] key;
        byte[] toProc;
        int toOffset;
        int toLen = (confounder == null ? 0 : confounder.length)
                + (header == null ? 0 : header.length) + len + paddingLen;
        if (toLen == len) {
            toProc = data;
            toOffset = offset;
        } else {
            toOffset = 0;
            int idx = 0;
            toProc = new byte[toLen];

            if (header != null) {
                System.arraycopy(header, 0, toProc, idx, header.length);
                idx += header.length;
            }

            if (confounder != null) {
                System.arraycopy(confounder, 0, toProc, idx, confounder.length);
                idx += confounder.length;
            }

            System.arraycopy(data, offset, toProc, idx, len);
            addPadding(paddingLen, toProc, len + idx);
        }

        CheckSumType chksumType;
        try {
            switch (sgnAlg) {
                case GssTokenV1.SGN_ALG_DES_MAC_MD5:
                    Md5Provider md5Provider = new Md5Provider();
                    md5Provider.hash(toProc);
                    toProc = md5Provider.output();

                case GssTokenV1.SGN_ALG_DES_MAC:
                    DesProvider desProvider = new DesProvider();
                    return desProvider.cbcMac(encKeyBytes, IV_ZEROR_8B, toProc);

                case GssTokenV1.SGN_ALG_HMAC_SHA1_DES3_KD:
                    chksumType = CheckSumType.HMAC_SHA1_DES3_KD;
                    break;
                case GssTokenV1.SGN_ALG_RC4_HMAC:
                    chksumType = CheckSumType.MD5_HMAC_ARCFOUR;
                    if (isMic) {
                        keyUsage = GssTokenV1.KG_USAGE_MS_SIGN;
                    }
                    break;
                case GssTokenV1.SGN_ALG_MD25:
                    throw new GSSException(GSSException.FAILURE, -1, "CheckSum not implemented for SGN_ALG_MD25");
                default:
                    throw new GSSException(GSSException.FAILURE, -1, "CheckSum not implemented for sgnAlg=" + sgnAlg);
            }
            handler = CheckSumHandler.getCheckSumHandler(chksumType);
            keySize = handler.keySize();
            key = getKeyBytesWithLength(keySize);
            ret = handler.checksumWithKey(toProc, toOffset, toLen, key, keyUsage);
        } catch (KrbException e) {
            throw new GSSException(GSSException.FAILURE, -1,
                    "Exception in checksum calculation sgnAlg = " + sgnAlg + " : " + e.getMessage());
        }
        return ret;
    }

    public byte[] encryptSequenceNumber(byte[] seqBytes, byte[] ivSrc, boolean encrypt)
            throws GSSException {
        EncTypeHandler handler;
        try {
            switch (sgnAlg) {
                case GssTokenV1.SGN_ALG_DES_MAC_MD5:
                case GssTokenV1.SGN_ALG_DES_MAC:
                    DesProvider desProvider = new DesProvider();
                    byte[] data = seqBytes.clone();
                    if (encrypt) {
                        desProvider.encrypt(encKeyBytes, ivSrc, data);
                    } else {
                        desProvider.decrypt(encKeyBytes, ivSrc, data);
                    }
                    return data;
                case GssTokenV1.SGN_ALG_HMAC_SHA1_DES3_KD:
                    handler = EncryptionHandler.getEncHandler(EncryptionType.DES3_CBC_SHA1_KD);
                    break;
                case GssTokenV1.SGN_ALG_RC4_HMAC:
                    return encryptArcFourHmac(seqBytes, getKeyBytesWithLength(16), getFirstBytes(ivSrc, 8), encrypt);
                case GssTokenV1.SGN_ALG_MD25:
                    throw new GSSException(GSSException.FAILURE, -1, "EncSeq not implemented for SGN_ALG_MD25");
                default:
                    throw new GSSException(GSSException.FAILURE, -1, "EncSeq not implemented for sgnAlg=" + sgnAlg);
            }
            int keySize = handler.keySize();
            byte[] key = getKeyBytesWithLength(keySize);
            int ivLen = handler.encProvider().blockSize();
            byte[] iv = getFirstBytes(ivSrc, ivLen);
            if (encrypt) {
                return handler.encryptRaw(seqBytes, key, iv, GssTokenV1.KG_USAGE_SEQ);
            } else {
                return handler.decryptRaw(seqBytes, key, iv, GssTokenV1.KG_USAGE_SEQ);
            }
        } catch (KrbException e) {
            throw new GSSException(GSSException.FAILURE, -1,
                    "Exception in encrypt seq number sgnAlg = " + sgnAlg + " : " + e.getMessage());
        }
    }

    private byte[] getHmacMd5(byte[] key, byte[] salt) throws GSSException {
        try {
            SecretKey secretKey = new SecretKeySpec(key, "HmacMD5");
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(secretKey);
            return mac.doFinal(salt);
        } catch (Exception e) {
            throw new GSSException(GSSException.FAILURE, -1, "Get HmacMD5 failed: " + e.getMessage());
        }
    }

    private byte[] encryptArcFourHmac(byte[] data, byte[] key, byte[] iv, boolean encrypt)
            throws GSSException {
        byte[] sk1 = getHmacMd5(key, new byte[4]);
        byte[] sk2 = getHmacMd5(sk1, iv);
        Rc4Provider provider = new Rc4Provider();
        try {
            byte[] ret = data.clone();
            if (encrypt) {
                provider.encrypt(sk2, ret);
            } else {
                provider.decrypt(sk2, ret);
            }
            return ret;
        } catch (KrbException e) {
            throw new GSSException(GSSException.FAILURE, -1,
                    "En/Decrypt sequence failed for ArcFourHmac: " + e.getMessage());
        }
    }

    private byte[] encryptDataArcFourHmac(byte[] data, byte[] key, byte[] seqNum, boolean encrypt) throws GSSException {
        byte[] dataKey = new byte[key.length];
        for (int i = 0; i <= 15; i++) {
            dataKey[i] = (byte) (key[i] ^ 0xF0);
        }
        return encryptArcFourHmac(data, dataKey, seqNum, encrypt);
    }

    public byte[] encryptTokenV1(byte[] confounder, byte[] data, int offset, int len,
                            int paddingLen, byte[] seqNumber, boolean encrypt) throws GSSException {
        byte[] toProc;
        if (encrypt) {
            int toLen = (confounder == null ? 0 : confounder.length) + len + paddingLen;
            int index = 0;
            toProc = new byte[toLen];
            if (confounder != null) {
                System.arraycopy(confounder, 0, toProc, 0, confounder.length);
                index += confounder.length;
            }
            System.arraycopy(data, offset, toProc, index, len);
            addPadding(paddingLen, toProc, index + len);
        } else {
            toProc = data;
            if (data.length != len) {
                toProc = new byte[len];
                System.arraycopy(data, offset, toProc, 0, len);
            }
        }
        EncTypeHandler handler;
        try {
            switch (sealAlg) {
                case GssTokenV1.SEAL_ALG_DES:
                    handler = EncryptionHandler.getEncHandler(EncryptionType.DES_CBC_MD5);
                    break;
                case GssTokenV1.SEAL_ALG_DES3_KD:
                    handler = EncryptionHandler.getEncHandler(EncryptionType.DES3_CBC_SHA1_KD);
                    break;
                case GssTokenV1.SEAL_ALG_RC4_HMAC:
                    return encryptDataArcFourHmac(toProc, getKeyBytesWithLength(16), seqNumber, encrypt);
                default:
                    throw new GSSException(GSSException.FAILURE, -1, "Unknown encryption type sealAlg = " + sealAlg);
            }

            int keySize = handler.keySize();
            byte[] key = getKeyBytesWithLength(keySize);
            if (encrypt) {
                return handler.encryptRaw(toProc, key, GssTokenV1.KG_USAGE_SEAL);
            } else {
                return handler.decryptRaw(toProc, key, GssTokenV1.KG_USAGE_SEAL);
            }
        } catch (KrbException e) {
            throw new GSSException(GSSException.FAILURE, -1,
                    "Exception in encrypt data sealAlg = " + sealAlg + " : " + e.getMessage());
        }
    }
}