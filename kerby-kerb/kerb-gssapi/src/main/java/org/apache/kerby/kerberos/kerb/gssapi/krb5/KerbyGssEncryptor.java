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
package org.apache.kerby.kerberos.kerb.gssapi.krb5;


import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.CheckSumHandler;
import org.apache.kerby.kerberos.kerb.crypto.CheckSumTypeHandler;
import org.apache.kerby.kerberos.kerb.crypto.EncTypeHandler;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.ietf.jgss.GSSException;

/**
 * This class implements encryption related function used in GSS tokens
 */
public class KerbyGssEncryptor {

    private EncryptionKey encKey;
    private boolean isV2 = false;

    public KerbyGssEncryptor(EncryptionKey key) throws GSSException {
        encKey = key;
        EncryptionType keyType = key.getKeyType();
        // TODO: add support for other algorithms
        if (keyType == EncryptionType.AES128_CTS_HMAC_SHA1_96
                || keyType == EncryptionType.AES256_CTS_HMAC_SHA1_96) {
            isV2 = true;
        } else {
            throw new GSSException(GSSException.FAILURE, -1,
                    "Invalid encryption type: " + key.getKeyType().getDisplayName());
        }
    }

    /**
     * Return true if it is encryption type defined in RFC 4121
     * @return
     */
    public boolean isV2() {
        return isV2;
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
            return getCheckSumHandler().checksumWithKey(buffer, encKey.getKeyData(), keyUsage);
        } catch (KrbException e) {
            throw new GSSException(GSSException.FAILURE, -1,
                    "Exception in checksum calculation:" + encKey.getKeyType().getName());
        }
    }

    private CheckSumTypeHandler getCheckSumHandler() throws GSSException {
        CheckSumType checkSumType;
        if (encKey.getKeyType() == EncryptionType.AES128_CTS_HMAC_SHA1_96) {
            checkSumType = CheckSumType.HMAC_SHA1_96_AES128;
        } else if (encKey.getKeyType() == EncryptionType.AES256_CTS_HMAC_SHA1_96) {
            checkSumType = CheckSumType.HMAC_SHA1_96_AES256;
        } else {
            throw new GSSException(GSSException.FAILURE, -1,
                    "Unsupported checksum encryption type:" + encKey.getKeyType().getName());
        }
        try {
            return CheckSumHandler.getCheckSumHandler(checkSumType);
        } catch (KrbException e) {
            throw new GSSException(GSSException.FAILURE, -1,
                    "Unsupported checksum type:" + checkSumType.getName());
        }
    }

    /**
     * Get the size of the corresponding checksum algorithm
     * @return
     * @throws GSSException
     */
    public int getCheckSumSize() throws GSSException {
        return getCheckSumHandler().cksumSize();
    }
}
