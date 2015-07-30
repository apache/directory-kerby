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

import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.crypto.key.DkKeyMaker;
import org.apache.kerby.kerberos.kerb.crypto.util.Cmac;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;

import java.nio.charset.Charset;

public abstract class KeKiCmacEnc extends KeKiEnc {

    private DkKeyMaker km;
    private EncryptionType eType; //NOPMD
    
    public KeKiCmacEnc(EncryptProvider encProvider,
                       EncryptionType eType, DkKeyMaker km) {
        super(encProvider, null);
        this.eType = eType;
        this.km = km;

    }


    @Override
    public int checksumSize() {
        return encProvider().blockSize();
    }

    @Override
    public byte[] prf(byte[] key, byte[] seed) throws KrbException {
        byte[] prfConst = "prf".getBytes(Charset.forName("UTF-8"));
        byte[] kp;
        if (EncryptionHandler.getEncHandler(this.eType()).prfSize() != encProvider().blockSize()) {
            return null;
        }
        kp = km.dk(key, prfConst);
        return Cmac.cmac(encProvider(), kp, seed);
    }

    @Override
    protected byte[] makeChecksum(byte[] key, byte[] data, int hashSize)
            throws KrbException {

        // generate hash
        byte[] hash = Cmac.cmac(encProvider(), key, data);

        // truncate hash
        byte[] output = new byte[hashSize];
        System.arraycopy(hash, 0, output, 0, hashSize);
        return output;
    }
}
