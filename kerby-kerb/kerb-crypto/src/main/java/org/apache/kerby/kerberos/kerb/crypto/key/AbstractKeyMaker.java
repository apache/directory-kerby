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

import org.apache.kerby.kerberos.kerb.crypto.util.BytesUtil;
import org.apache.kerby.kerberos.kerb.crypto.enc.EncryptProvider;
import org.apache.kerby.kerberos.kerb.KrbException;

import java.io.UnsupportedEncodingException;

public abstract class AbstractKeyMaker implements KeyMaker {

    protected static final byte[] KERBEROS_CONSTANT = "kerberos".getBytes();

    private EncryptProvider encProvider;

    public AbstractKeyMaker(EncryptProvider encProvider) {
        this.encProvider = encProvider;
    }

    protected EncryptProvider encProvider() {
        return encProvider;
    }

    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        return new byte[0];
    }

    /**
     * Visible for test
     */
    public static byte[] makePasswdSalt(String password, String salt) {
        char[] chars = new char[password.length() + salt.length()];
        System.arraycopy(password.toCharArray(), 0, chars, 0, password.length());
        System.arraycopy(salt.toCharArray(), 0, chars, password.length(), salt.length());

        try {
            return new String(chars).getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Character decoding failed", e);
        }
    }

    protected static int getIterCount(byte[] param, int defCount) {
        int iterCount = defCount;

        if (param != null) {
            if (param.length != 4) {
                throw new IllegalArgumentException("Invalid param to str2Key");
            }
            iterCount = BytesUtil.bytes2int(param, 0, true);
        }

        return iterCount;
    }

    protected static byte[] getSaltBytes(String salt, String pepper)
            throws UnsupportedEncodingException {
        byte[] saltBytes = salt.getBytes("UTF-8");
        if (pepper != null && ! pepper.isEmpty()) {
            byte[] pepperBytes = pepper.getBytes("UTF-8");
            int len = saltBytes.length;
            len += 1 + pepperBytes.length;
            byte[] results = new byte[len];
            System.arraycopy(pepperBytes, 0, results, 0, pepperBytes.length);
            results[pepperBytes.length] = (byte) 0;
            System.arraycopy(saltBytes, 0,
                    results, pepperBytes.length + 1, saltBytes.length);

            return results;
        } else {
            return saltBytes;
        }
    }
}
