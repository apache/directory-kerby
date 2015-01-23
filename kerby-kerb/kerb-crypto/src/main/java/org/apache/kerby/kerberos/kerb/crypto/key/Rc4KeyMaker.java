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

import org.apache.kerby.kerberos.kerb.crypto.enc.EncryptProvider;
import org.apache.kerby.kerberos.kerb.KrbException;
import sun.security.provider.MD4;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;

public class Rc4KeyMaker extends AbstractKeyMaker {

    public Rc4KeyMaker(EncryptProvider encProvider) {
        super(encProvider);
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {

        if (param != null && param.length > 0) {
            throw new RuntimeException("Invalid param to str2Key");
        }

        try {
            byte[] passwd = string.getBytes("UTF-16LE"); // to unicode
            MessageDigest md = MD4.getInstance();
            md.update(passwd);
            return md.digest();
        } catch (UnsupportedEncodingException e) {
            throw new KrbException("str2key failed", e);
        }
    }

}
