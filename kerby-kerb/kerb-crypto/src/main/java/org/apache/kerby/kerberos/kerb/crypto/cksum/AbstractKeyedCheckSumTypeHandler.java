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

import org.apache.kerby.kerberos.kerb.crypto.enc.EncryptProvider;
import org.apache.kerby.kerberos.kerb.crypto.key.KeyMaker;
import org.apache.kerby.kerberos.kerb.KrbException;

public abstract class AbstractKeyedCheckSumTypeHandler extends AbstractCheckSumTypeHandler {

    private KeyMaker keyMaker;

    public AbstractKeyedCheckSumTypeHandler(EncryptProvider encProvider, HashProvider hashProvider,
                                            int computeSize, int outputSize) {
        super(encProvider, hashProvider, computeSize, outputSize);
    }

    protected void keyMaker(KeyMaker keyMaker) {
        this.keyMaker = keyMaker;
    }

    protected KeyMaker keyMaker() {
        return keyMaker;
    }

    @Override
    public byte[] checksumWithKey(byte[] data,
                                  byte[] key, int usage) throws KrbException {
        return checksumWithKey(data, 0, data.length, key, usage);
    }

    @Override
    public byte[] checksumWithKey(byte[] data, int start, int len,
                                  byte[] key, int usage) throws KrbException {
        int outputSize = outputSize();

        byte[] tmp = doChecksumWithKey(data, start, len, key, usage);
        if (outputSize < tmp.length) {
            byte[] output = new byte[outputSize];
            System.arraycopy(tmp, 0, output, 0, outputSize);
            return output;
        } else {
            return tmp;
        }
    }

    protected byte[] doChecksumWithKey(byte[] data, int start, int len,
                                       byte[] key, int usage) throws KrbException {
        return new byte[0];
    }

    @Override
    public boolean verifyWithKey(byte[] data, byte[] key,
                                 int usage, byte[] checksum) throws KrbException {
        byte[] newCksum = checksumWithKey(data, key, usage);
        return checksumEqual(checksum, newCksum);
    }
}
