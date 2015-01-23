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

import org.apache.kerby.kerberos.kerb.KrbException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MessageDigestHashProvider extends AbstractHashProvider {
    private String algorithm;
    protected MessageDigest messageDigest;

    public MessageDigestHashProvider(int hashSize, int blockSize, String algorithm) {
        super(hashSize, blockSize);
        this.algorithm = algorithm;

        init();
    }

    @Override
    protected void init() {
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to init JCE provider", e);
        }
    }

    @Override
    public void hash(byte[] data, int start, int len) throws KrbException {
        messageDigest.update(data, start, len);
    }

    @Override
    public byte[] output() {
        return messageDigest.digest();
    }
}
