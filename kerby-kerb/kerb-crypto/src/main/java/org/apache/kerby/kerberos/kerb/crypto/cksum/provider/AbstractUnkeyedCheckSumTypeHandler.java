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
package org.apache.kerby.kerberos.kerb.crypto.cksum.provider;

import org.apache.kerby.kerberos.kerb.crypto.cksum.AbstractCheckSumTypeHandler;
import org.apache.kerby.kerberos.kerb.crypto.cksum.HashProvider;
import org.apache.kerby.kerberos.kerb.KrbException;

public abstract class AbstractUnkeyedCheckSumTypeHandler extends AbstractCheckSumTypeHandler {

    public AbstractUnkeyedCheckSumTypeHandler(HashProvider hashProvider,
                                              int computeSize, int outputSize) {
        super(null, hashProvider, computeSize, outputSize);
    }

    @Override
    public byte[] checksum(byte[] data, int start, int len) throws KrbException {
        int outputSize = outputSize();

        HashProvider hp = hashProvider();
        hp.hash(data, start, len);
        byte[] workBuffer = hp.output();

        if (outputSize < workBuffer.length) {
            byte[] output = new byte[outputSize];
            System.arraycopy(workBuffer, 0, output, 0, outputSize);
            return output;
        }
        return workBuffer;
    }

    @Override
    public boolean verify(byte[] data, int start, int len, byte[] checksum) throws KrbException {
        byte[] newCksum = checksum(data, start, len);
        return checksumEqual(newCksum, checksum);
    }
}
