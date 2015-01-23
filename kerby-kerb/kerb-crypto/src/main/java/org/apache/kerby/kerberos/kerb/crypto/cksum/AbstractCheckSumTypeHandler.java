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

import org.apache.kerby.kerberos.kerb.crypto.AbstractCryptoTypeHandler;
import org.apache.kerby.kerberos.kerb.crypto.CheckSumTypeHandler;
import org.apache.kerby.kerberos.kerb.crypto.enc.EncryptProvider;
import org.apache.kerby.kerberos.kerb.KrbException;

public abstract class AbstractCheckSumTypeHandler
        extends AbstractCryptoTypeHandler implements CheckSumTypeHandler {

    private int computeSize;
    private int outputSize;

    public AbstractCheckSumTypeHandler(EncryptProvider encProvider, HashProvider hashProvider,
                                       int computeSize, int outputSize) {
        super(encProvider, hashProvider);
        this.computeSize = computeSize;
        this.outputSize = outputSize;
    }

    @Override
    public String name() {
        return cksumType().getName();
    }

    @Override
    public String displayName() {
        return cksumType().getDisplayName();
    }

    @Override
    public int computeSize() {
        return computeSize;
    }

    @Override
    public int outputSize() {
        return outputSize;
    }

    public boolean isSafe() {
        return false;
    }

    public int cksumSize() {
        return 4;
    }

    public int keySize() {
        return 0;
    }

    public int confounderSize() {
        return 0;
    }

    @Override
    public byte[] checksum(byte[] data) throws KrbException {
        return checksum(data, 0, data.length);
    }

    @Override
    public byte[] checksum(byte[] data, int start, int size) throws KrbException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean verify(byte[] data, byte[] checksum) throws KrbException {
        return verify(data, 0, data.length, checksum);
    }

    @Override
    public boolean verify(byte[] data, int start, int size, byte[] checksum) throws KrbException {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] checksumWithKey(byte[] data,
                                  byte[] key, int usage) throws KrbException {
        return checksumWithKey(data, 0, data.length, key, usage);
    }

    @Override
    public byte[] checksumWithKey(byte[] data, int start, int size,
                                  byte[] key, int usage) throws KrbException {
        throw new UnsupportedOperationException();
    }
    @Override
    public boolean verifyWithKey(byte[] data,
                                 byte[] key, int usage, byte[] checksum) throws KrbException {
        throw new UnsupportedOperationException();
    }
}
