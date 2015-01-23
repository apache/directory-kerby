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
package org.apache.kerby.kerberos.kerb.crypto.cksum;

import org.apache.kerby.kerberos.kerb.crypto.Confounder;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.DesProvider;
import org.apache.kerby.kerberos.kerb.KrbException;

import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;

public abstract class ConfounderedDesCheckSum extends AbstractKeyedCheckSumTypeHandler {

    public ConfounderedDesCheckSum(HashProvider hashProvider,
                                   int computeSize, int outputSize) {
        super(new DesProvider(), hashProvider, computeSize, outputSize);
    }

    @Override
    protected byte[] doChecksumWithKey(byte[] data, int start, int len,
                                       byte[] key, int usage) throws KrbException {
        int computeSize = computeSize();
        int blockSize = encProvider().blockSize();
        int hashSize = hashProvider().hashSize();

        byte[] workBuffer = new byte[computeSize];

        // confounder
        byte[] conf = Confounder.makeBytes(blockSize);

        // confounder | data
        byte[] toHash = new byte[blockSize + len];
        System.arraycopy(conf, 0, toHash, 0, blockSize);
        System.arraycopy(data, start, toHash, blockSize, len);

        HashProvider hashProvider = hashProvider();
        hashProvider.hash(toHash);
        byte[] hash = hashProvider.output();

        // confounder | hash
        System.arraycopy(conf, 0, workBuffer, 0, blockSize);
        System.arraycopy(hash, 0, workBuffer, blockSize, hashSize);

        // key
        byte[] newKey = deriveKey(key);

        encProvider().encrypt(newKey, workBuffer);
        return workBuffer;
    }

    protected byte[] deriveKey(byte[] key) {
        return fixKey(xorKey(key));
    }

    protected byte[] xorKey(byte[] key) {
        byte[] xorKey = new byte[encProvider().keySize()];
        System.arraycopy(key, 0, xorKey, 0, key.length);
        for (int i = 0; i < xorKey.length; i++) {
            xorKey[i] = (byte) (xorKey[i] ^ 0xf0);
        }

        return xorKey;
    }

    private byte[] fixKey(byte[] key) {
        boolean isWeak = true;
        try {
            isWeak = DESKeySpec.isWeak(key, 0);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        if (isWeak) {
            key[7] = (byte)(key[7] ^ 0xF0);
        }

        return key;
    }

    @Override
    public boolean verifyWithKey(byte[] data,byte[] key,
                                 int usage, byte[] checksum) throws KrbException {
        int computeSize = computeSize();
        int blockSize = encProvider().blockSize();
        int hashSize = hashProvider().hashSize();

        // key
        byte[] newKey = deriveKey(key);

        encProvider().decrypt(newKey, checksum);
        byte[] decrypted = checksum; // confounder | hash

        // confounder | data
        byte[] toHash = new byte[blockSize + data.length];
        System.arraycopy(decrypted, 0, toHash, 0, blockSize);
        System.arraycopy(data, 0, toHash, blockSize, data.length);

        HashProvider hashProvider = hashProvider();
        hashProvider.hash(toHash);
        byte[] newHash = hashProvider.output();

        return checksumEqual(newHash, decrypted, blockSize, hashSize);
    }
}
