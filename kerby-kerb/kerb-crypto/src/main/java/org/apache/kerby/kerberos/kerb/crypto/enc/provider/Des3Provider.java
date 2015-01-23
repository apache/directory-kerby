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
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;

public class Des3Provider extends AbstractEncryptProvider {

    public Des3Provider() {
        super(8, 21, 24);
    }

    @Override
    protected void doEncrypt(byte[] input, byte[] key,
                             byte[] cipherState, boolean encrypt) throws KrbException {

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        } catch (GeneralSecurityException e) {
            throw new KrbException("Failed to init cipher", e);
        }

        try {
            IvParameterSpec params = new IvParameterSpec(cipherState);
            KeySpec skSpec = new DESedeKeySpec(key, 0);

            SecretKeyFactory skf = SecretKeyFactory.getInstance("desede");
            SecretKey secretKey = skf.generateSecret(skSpec);

            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, params);

            byte[] output = cipher.doFinal(input);
            System.arraycopy(output, 0, input, 0, output.length);
        } catch (GeneralSecurityException e) {
            throw new KrbException("Failed to doEncrypt", e);
        }
    }

}
