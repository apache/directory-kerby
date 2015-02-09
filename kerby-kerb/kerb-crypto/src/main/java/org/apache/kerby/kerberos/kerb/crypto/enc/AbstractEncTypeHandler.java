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
package org.apache.kerby.kerberos.kerb.crypto.enc;

import org.apache.kerby.kerberos.kerb.crypto.AbstractCryptoTypeHandler;
import org.apache.kerby.kerberos.kerb.crypto.EncTypeHandler;
import org.apache.kerby.kerberos.kerb.crypto.cksum.HashProvider;
import org.apache.kerby.kerberos.kerb.crypto.key.KeyMaker;
import org.apache.kerby.kerberos.kerb.KrbException;

public abstract class AbstractEncTypeHandler
        extends AbstractCryptoTypeHandler implements EncTypeHandler {

    private KeyMaker keyMaker;

    public AbstractEncTypeHandler(EncryptProvider encProvider,
                                  HashProvider hashProvider) {
        super(encProvider, hashProvider);
    }

    protected void keyMaker(KeyMaker keyMaker) {
        this.keyMaker = keyMaker;
    }

    protected KeyMaker keyMaker() {
        return keyMaker;
    }

    @Override
    public String name() {
        return eType().getName();
    }

    @Override
    public String displayName() {
        return eType().getDisplayName();
    }

    protected int paddingLength(int inputLen) {
        int payloadLen = confounderSize() + checksumSize() + inputLen;
        int padding = paddingSize();

        if (padding == 0 || (payloadLen % padding) == 0) {
            return 0;
        }

        return padding - (payloadLen % padding);
    }

    @Override
    public int keyInputSize() {
        return encProvider().keyInputSize();
    }

    @Override
    public int keySize() {
        return encProvider().keySize();
    }

    @Override
    public int confounderSize() {
        return encProvider().blockSize();
    }

    @Override
    public int checksumSize() {
        return hashProvider().hashSize();
    }

    @Override
    public int paddingSize() {
        return encProvider().blockSize();
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        return keyMaker.str2key(string, salt, param);
    }

    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        return keyMaker.random2Key(randomBits);
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] key, int usage) throws KrbException {
        byte[] iv = new byte[encProvider().blockSize()];
        return encrypt(data, key, iv, usage);
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] key, byte[] iv, int usage) throws KrbException {
        int confounderLen = confounderSize();
        int checksumLen = checksumSize();
        int headerLen = confounderLen + checksumLen;
        int inputLen = data.length;
        int paddingLen = paddingLength(inputLen);

        /**
         *  E(Confounder | Checksum | Plaintext | Padding), or
         *  header | data | padding | trailer, where trailer may be absent
         */

        int workLength = headerLen + inputLen + paddingLen;

        byte[] workBuffer = new byte[workLength];
        System.arraycopy(data, 0, workBuffer, headerLen, data.length);

        int[] workLens = new int[] {confounderLen, checksumLen,
                inputLen, paddingLen};

        encryptWith(workBuffer, workLens, key, iv, usage);
        return workBuffer;
    }

    protected void encryptWith(byte[] workBuffer, int[] workLens,
                          byte[] key, byte[] iv, int usage) throws KrbException {

    }

    public byte[] decrypt(byte[] cipher, byte[] key, int usage)
            throws KrbException {
        byte[] iv = new byte[encProvider().blockSize()];
        return decrypt(cipher, key, iv, usage);
    }

    public byte[] decrypt(byte[] cipher, byte[] key, byte[] iv, int usage)
            throws KrbException {

        int totalLen = cipher.length;
        int confounderLen = confounderSize();
        int checksumLen = checksumSize();
        int dataLen = totalLen - (confounderLen + checksumLen);

        int[] workLens = new int[] {confounderLen, checksumLen, dataLen};
        return decryptWith(cipher, workLens, key, iv, usage);
    }

    protected byte[] decryptWith(byte[] workBuffer, int[] workLens,
                               byte[] key, byte[] iv, int usage) throws KrbException {
        return null;
    }
}
