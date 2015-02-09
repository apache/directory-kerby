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

import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.crypto.util.Confounder;
import org.apache.kerby.kerberos.kerb.crypto.cksum.HashProvider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.DesProvider;
import org.apache.kerby.kerberos.kerb.crypto.key.DesKeyMaker;
import org.apache.kerby.kerberos.kerb.KrbException;

abstract class DesCbcEnc extends AbstractEncTypeHandler {

    public DesCbcEnc(HashProvider hashProvider) {
        super(new DesProvider(), hashProvider);
        keyMaker(new DesKeyMaker(this.encProvider()));
    }

    @Override
    protected void encryptWith(byte[] workBuffer, int[] workLens,
                                 byte[] key, byte[] iv, int usage) throws KrbException {
        int confounderLen = workLens[0];
        int checksumLen = workLens[1];
        int dataLen = workLens[2];
        int paddingLen = workLens[3];

        // confounder
        byte[] confounder = Confounder.makeBytes(confounderLen);
        System.arraycopy(confounder, 0, workBuffer, 0, confounderLen);

        // padding
        for (int i = confounderLen + checksumLen + dataLen; i < paddingLen; ++i) {
            workBuffer[i] = 0;
        }

        // checksum
        hashProvider().hash(workBuffer);
        byte[] cksum = hashProvider().output();
        System.arraycopy(cksum, 0, workBuffer, confounderLen, checksumLen);

        encProvider().encrypt(key, iv, workBuffer);
    }

    @Override
    protected byte[] decryptWith(byte[] workBuffer, int[] workLens,
                                 byte[] key, byte[] iv, int usage) throws KrbException {
        int confounderLen = workLens[0];
        int checksumLen = workLens[1];
        int dataLen = workLens[2];

        encProvider().decrypt(key, iv, workBuffer);

        byte[] checksum = new byte[checksumLen];
        for (int i = 0; i < checksumLen; i++) {
            checksum[i] = workBuffer[confounderLen + i];
            workBuffer[confounderLen + i] = 0;
        }

        hashProvider().hash(workBuffer);
        byte[] newChecksum = hashProvider().output();
        if (! checksumEqual(checksum, newChecksum)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY);
        }

        byte[] data = new byte[dataLen];
        System.arraycopy(workBuffer, confounderLen + checksumLen,
                data, 0, dataLen);

        return data;
    }
}
