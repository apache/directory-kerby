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
import org.apache.kerby.kerberos.kerb.crypto.util.Des;
import org.apache.kerby.kerberos.kerb.crypto.util.Nfold;
import org.apache.kerby.kerberos.kerb.crypto.enc.EncryptProvider;

public class Des3KeyMaker extends DkKeyMaker {

    public Des3KeyMaker(EncryptProvider encProvider) {
        super(encProvider);
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        byte[] utf8Bytes = makePasswdSalt(string, salt);
        int keyInputSize = encProvider().keyInputSize();
        byte[] tmpKey = random2Key(Nfold.nfold(utf8Bytes, keyInputSize));
        return dk(tmpKey, KERBEROS_CONSTANT);
    }

    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        if (randomBits.length != encProvider().keyInputSize()) {
            throw new KrbException("Invalid random bits, not of correct bytes size");
        }
        /**
         * Ref. k5_rand2key_des3 in random_to_key.c in MIT krb5
         * Take the seven bytes, move them around into the top 7 bits of the
         * 8 key bytes, then compute the parity bits.  Do this three times.
         */
        byte[] key = new byte[encProvider().keySize()];
        for (int i = 0; i < 3; i++) {
            System.arraycopy(randomBits, i * 7, key, i * 8, 7);
            int nthByte = i * 8;

            key[nthByte + 7] = (byte) (((key[nthByte + 0] & 1) << 1) |
                    ((key[nthByte + 1] & 1) << 2) |
                    ((key[nthByte + 2] & 1) << 3) |
                    ((key[nthByte + 3] & 1) << 4) |
                    ((key[nthByte + 4] & 1) << 5) |
                    ((key[nthByte + 5] & 1) << 6) |
                    ((key[nthByte + 6] & 1) << 7));

            for (int j = 0; j < 8; j++) {
                int tmp = key[nthByte + j] & 0xfe;
                tmp |= (Integer.bitCount(tmp) & 1) ^ 1;
                key[nthByte + j] = (byte) tmp;
            }
        }

        for (int i = 0; i < 3; i++) {
            Des.fixKey(key, i * 8, 8);
        }

        return key;
    }
}
