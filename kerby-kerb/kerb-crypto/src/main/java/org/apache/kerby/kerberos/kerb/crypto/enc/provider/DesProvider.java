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

public class DesProvider extends AbstractEncryptProvider {

    public DesProvider() {
        super(8, 7, 8);
    }

    @Override
    protected void doEncrypt(byte[] input, byte[] key,
                                 byte[] cipherState, boolean encrypt) throws KrbException {

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("DES/CBC/NoPadding");
        } catch (GeneralSecurityException e) {
            throw new KrbException("Failed to init cipher", e);
        }
        IvParameterSpec params = new IvParameterSpec(cipherState);
        SecretKeySpec skSpec = new SecretKeySpec(key, "DES");
        try {
            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, skSpec, params);

            byte[] output = cipher.doFinal(input);
            System.arraycopy(output, 0, input, 0, output.length);
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }
    }

    @Override
    public byte[] cbcMac(byte[] key, byte[] cipherState, byte[] data) throws KrbException {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("DES/CBC/NoPadding");
        } catch (GeneralSecurityException e) {
            throw new KrbException("Failed to init cipher", e);
        }
        IvParameterSpec params = new IvParameterSpec(cipherState);
        SecretKeySpec skSpec = new SecretKeySpec(key, "DES");

        byte[] output = null;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, skSpec, params);
            for (int i = 0; i < data.length / 8; i++) {
                output = cipher.doFinal(data, i * 8, 8);
                cipher.init(Cipher.ENCRYPT_MODE, skSpec, (new IvParameterSpec(output)));
            }
        }
        catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }
        return output;
    }

    @Override
    public boolean supportCbcMac() {
        return true;
    }
}
