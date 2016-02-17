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

import org.apache.kerby.kerberos.kerb.crypto.key.DkKeyMaker;
import org.apache.kerby.kerberos.kerb.crypto.util.Hmac;
import org.apache.kerby.kerberos.kerb.crypto.cksum.HashProvider;
import org.apache.kerby.kerberos.kerb.KrbException;

import java.nio.charset.StandardCharsets;

public abstract class KeKiHmacSha1Enc extends KeKiEnc {

    private DkKeyMaker km;

    public KeKiHmacSha1Enc(EncryptProvider encProvider,
                           HashProvider hashProvider, DkKeyMaker km) {
        super(encProvider, hashProvider);
        this.km = km;
    }

    @Override
    public byte[] prf(byte[] key, byte[] seed) throws KrbException {
        byte[] prfConst = "prf".getBytes(StandardCharsets.UTF_8);
        int cksumSize = (hashProvider().hashSize() / encProvider().blockSize())
            * encProvider().blockSize();
        byte[] cksum = new byte[cksumSize];
        byte[] kp;
        byte[] output = new byte[prfSize()];
        hashProvider().hash(seed);
        System.arraycopy(hashProvider().output(), 0, cksum, 0, cksumSize);
        kp = km.dk(key, prfConst);
        encProvider().encrypt(kp, cksum);
        System.arraycopy(cksum, 0, output, 0, this.prfSize());
        return output;
    }

    @Override
    protected byte[] makeChecksum(byte[] key, byte[] data, int hashSize)
            throws KrbException {

        // generate hash
        byte[] hash = Hmac.hmac(hashProvider(), key, data);

        // truncate hash
        byte[] output = new byte[hashSize];
        System.arraycopy(hash, 0, output, 0, hashSize);
        return output;
    }
}
