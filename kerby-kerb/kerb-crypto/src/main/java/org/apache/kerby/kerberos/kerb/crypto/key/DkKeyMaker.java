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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.util.Nfold;
import org.apache.kerby.kerberos.kerb.crypto.enc.EncryptProvider;

public abstract class DkKeyMaker extends AbstractKeyMaker {

    public DkKeyMaker(EncryptProvider encProvider) {
        super(encProvider);
    }

    // DK(Key, Constant) = random-to-key(DR(Key, Constant))
    public byte[] dk(byte[] key, byte[] constant) throws KrbException {
        return random2Key(dr(key, constant));
    }

    /*
     * K1 = E(Key, n-fold(Constant), initial-cipher-state)
     * K2 = E(Key, K1, initial-cipher-state)
     * K3 = E(Key, K2, initial-cipher-state)
     * K4 = ...
     * DR(Key, Constant) = k-truncate(K1 | K2 | K3 | K4 ...)
     */
    protected byte[] dr(byte[] key, byte[] constant) throws KrbException {

        int blocksize = encProvider().blockSize();
        int keyInuptSize = encProvider().keyInputSize();
        byte[] keyBytes = new byte[keyInuptSize];
        byte[] Ki;

        if (constant.length != blocksize) {
            Ki = Nfold.nfold(constant, blocksize);
        } else {
            Ki = new byte[constant.length];
            System.arraycopy(constant, 0, Ki, 0, constant.length);
        }

        int n = 0, len;
        while (n < keyInuptSize) {
            encProvider().encrypt(key, Ki);

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
