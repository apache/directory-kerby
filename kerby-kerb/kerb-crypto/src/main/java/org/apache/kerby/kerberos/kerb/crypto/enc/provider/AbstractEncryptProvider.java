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

import org.apache.kerby.kerberos.kerb.crypto.enc.EncryptProvider;
import org.apache.kerby.kerberos.kerb.KrbException;

public abstract class AbstractEncryptProvider implements EncryptProvider {
    private int blockSize;
    private int keyInputSize;
    private int keySize;

    public AbstractEncryptProvider(int blockSize, int keyInputSize, int keySize) {
        this.blockSize = blockSize;
        this.keyInputSize = keyInputSize;
        this.keySize = keySize;
    }

    @Override
    public int keyInputSize() {
        return keyInputSize;
    }

    @Override
    public int keySize() {
        return keySize;
    }

    @Override
    public int blockSize() {
        return blockSize;
    }

    @Override
    public byte[] initState(byte[] key, int keyUsage) {
        return new byte[0];
    }

    @Override
    public void encrypt(byte[] key, byte[] cipherState, byte[] data) throws KrbException {
        doEncrypt(data, key, cipherState, true);
    }

    @Override
    public void decrypt(byte[] key, byte[] cipherState, byte[] data) throws KrbException {
        doEncrypt(data, key, cipherState, false);
    }

    @Override
    public void encrypt(byte[] key, byte[] data) throws KrbException {
        byte[] cipherState = new byte[blockSize()];
        encrypt(key, cipherState, data);
    }

    @Override
    public void decrypt(byte[] key, byte[] data) throws KrbException {
        byte[] cipherState = new byte[blockSize()];
        decrypt(key, cipherState, data);
    }

    protected abstract void doEncrypt(byte[] data, byte[] key, byte[] cipherState, boolean encrypt) throws KrbException;

    @Override
    public byte[] cbcMac(byte[] key, byte[] iv, byte[] data) throws KrbException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean supportCbcMac() {
        return false;
    }

    @Override
    public void cleanState() {

    }

    @Override
    public void cleanKey() {

    }
}
