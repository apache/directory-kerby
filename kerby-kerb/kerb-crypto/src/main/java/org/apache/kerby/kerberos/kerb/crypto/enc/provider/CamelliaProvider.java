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

import org.apache.kerby.kerberos.kerb.crypto.Camellia;
import org.apache.kerby.kerberos.kerb.KrbException;

public abstract class CamelliaProvider extends AbstractEncryptProvider {

    public CamelliaProvider(int blockSize, int keyInputSize, int keySize) {
        super(blockSize, keyInputSize, keySize);
    }

    @Override
    protected void doEncrypt(byte[] data, byte[] key,
                             byte[] cipherState, boolean encrypt) throws KrbException {

        Camellia cipher = new Camellia();
        cipher.setKey(encrypt, key);
        if (encrypt) {
            cipher.encrypt(data, cipherState);
        } else {
            cipher.decrypt(data, cipherState);
        }
    }

    @Override
    public boolean supportCbcMac() {
        return true;
    }

    @Override
    public byte[] cbcMac(byte[] key, byte[] cipherState, byte[] data) {
        Camellia cipher = new Camellia();
        cipher.setKey(true, key);

        int blocksNum = data.length / blockSize();
        cipher.cbcEnc(data, 0, blocksNum, cipherState);
        return data;
    }
}
