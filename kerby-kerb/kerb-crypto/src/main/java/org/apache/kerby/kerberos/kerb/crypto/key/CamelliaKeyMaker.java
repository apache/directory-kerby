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
package org.apache.kerby.kerberos.kerb.crypto.key;

import org.apache.kerby.kerberos.kerb.crypto.BytesUtil;
import org.apache.kerby.kerberos.kerb.crypto.Cmac;
import org.apache.kerby.kerberos.kerb.crypto.Pbkdf;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.CamelliaProvider;
import org.apache.kerby.kerberos.kerb.KrbException;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

public class CamelliaKeyMaker extends DkKeyMaker {

    public CamelliaKeyMaker(CamelliaProvider encProvider) {
        super(encProvider);
    }

    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        return randomBits;
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        int iterCount = getIterCount(param, 32768);

        byte[] saltBytes = null;
        try {
            saltBytes = getSaltBytes(salt, getPepper());
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        int keySize = encProvider().keySize();
        byte[] random = new byte[0];
        try {
            random = Pbkdf.PBKDF2(string.toCharArray(), saltBytes, iterCount, keySize);
        } catch (GeneralSecurityException e) {
            throw new KrbException("PBKDF2 failed", e);
        }

        byte[] tmpKey = random2Key(random);
        byte[] result = dk(tmpKey, KERBEROS_CONSTANT);

        return result;
    }

    private String getPepper() {
        int keySize = encProvider().keySize();
        String pepper = keySize == 16 ? "camellia128-cts-cmac" : "camellia256-cts-cmac";
        return pepper;
    }

    /*
     * NIST SP800-108 KDF in feedback mode (section 5.2).
     */
    @Override
    protected byte[] dr(byte[] key, byte[] constant) throws KrbException {

        int blocksize = encProvider().blockSize();
        int keyInuptSize = encProvider().keyInputSize();
        byte[] keyBytes = new byte[keyInuptSize];
        byte[] Ki;

        int len = 0;
        // K(i-1): the previous block of PRF output, initially all-zeros.
        len += blocksize;
        // four-byte big-endian binary string giving the block counter
        len += 4;
        // the fixed derived-key input
        len += constant.length;
        // 0x00: separator byte
        len += 1;
        // four-byte big-endian binary string giving the output length
        len += 4;

        Ki = new byte[len];
        System.arraycopy(constant, 0, Ki, blocksize + 4, constant.length);
        BytesUtil.int2bytes(keyInuptSize * 8, Ki, len - 4, true);

        int i, n = 0;
        byte[] tmp;
        for (i = 1, n = 0; n < keyInuptSize; i++) {
            // Update the block counter
            BytesUtil.int2bytes(i, Ki, blocksize, true);

            // Compute a CMAC checksum, update Ki with the result
            tmp = Cmac.cmac(encProvider(), key, Ki);
            System.arraycopy(tmp, 0, Ki, 0, blocksize);

            if (n + blocksize >= keyInuptSize) {
                System.arraycopy(Ki, 0, keyBytes, n, keyInuptSize - n);
                break;
            }

            System.arraycopy(Ki, 0, keyBytes, n, blocksize);
            n += blocksize;
        }

        return keyBytes;
    }
}
