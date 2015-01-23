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

import org.apache.kerby.kerberos.kerb.crypto.cksum.HashProvider;
import org.apache.kerby.kerberos.kerb.KrbException;

public abstract class AbstractHashProvider implements HashProvider {
    private int blockSize;
    private int hashSize;

    public AbstractHashProvider(int hashSize, int blockSize) {
        this.hashSize = hashSize;
        this.blockSize = blockSize;
    }

    protected void init() {

    }

    @Override
    public int hashSize() {
        return hashSize;
    }

    @Override
    public int blockSize() {
        return blockSize;
    }

    @Override
    public void hash(byte[] data) throws KrbException {
        hash(data, 0, data.length);
    }
}
