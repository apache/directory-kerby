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
package org.apache.kerby.kerberos.kerb.crypto.enc.provider;

import org.apache.kerby.kerberos.kerb.KrbException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public abstract class AesProvider extends AbstractEncryptProvider {

    public AesProvider(int blockSize, int keyInputSize, int keySize) {
        super(blockSize, keyInputSize, keySize);
    }

    @Override
    protected void doEncrypt(byte[] data, byte[] key,
                                  byte[] cipherState, boolean encrypt) throws KrbException {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CTS/NoPadding");
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException("JCE provider may not be installed. "
                    + e.getMessage());
            ke.initCause(e);
            throw ke;
        }

        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            IvParameterSpec param = new IvParameterSpec(cipherState);

            cipher.init(encrypt ?
                    Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, param);
            byte[] output = cipher.doFinal(data);
            System.arraycopy(output, 0, data, 0, output.length);
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }
    }
}
