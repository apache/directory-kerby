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
package org.apache.kerby.kerberos.kerb.crypto;

import org.apache.kerby.kerberos.kerb.crypto.cksum.HashProvider;
import org.apache.kerby.kerberos.kerb.crypto.enc.EncryptProvider;

import java.util.Arrays;

public abstract class AbstractCryptoTypeHandler implements CryptoTypeHandler {

    private EncryptProvider encProvider;
    private HashProvider hashProvider;

    public AbstractCryptoTypeHandler(EncryptProvider encProvider,
                                     HashProvider hashProvider) {
        this.encProvider = encProvider;
        this.hashProvider = hashProvider;
    }

    @Override
    public EncryptProvider encProvider() {
        return encProvider;
    }

    @Override
    public HashProvider hashProvider() {
        return hashProvider;
    }

    protected static boolean checksumEqual(byte[] cksum1, byte[] cksum2) {
        return Arrays.equals(cksum1, cksum2);
    }

    protected static boolean checksumEqual(byte[] cksum1,
                                           byte[] cksum2, int cksum2Start, int len) {
        if (cksum1 == cksum2)
            return true;
        if (cksum1 == null || cksum2 == null)
            return false;

        if (len <= cksum2.length && len <= cksum1.length) {
            for (int i = 0; i < len; i++)
                if (cksum1[i] != cksum2[cksum2Start + i])
                    return false;
        } else {
            return false;
        }

        return true;
    }
}
