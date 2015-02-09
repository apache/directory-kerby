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

import org.apache.kerby.kerberos.kerb.crypto.util.Hmac;
import org.apache.kerby.kerberos.kerb.crypto.util.Rc4;
import org.apache.kerby.kerberos.kerb.crypto.cksum.provider.Md5Provider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.Rc4Provider;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.common.CheckSumType;

public class Md5HmacRc4CheckSum extends AbstractKeyedCheckSumTypeHandler {

    public Md5HmacRc4CheckSum() {
        super(new Rc4Provider(), new Md5Provider(), 16, 16);
    }

    public int confounderSize() {
        return 8;
    }

    public CheckSumType cksumType() {
        return CheckSumType.MD5_HMAC_ARCFOUR;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 16;  // bytes
    }

    public int keySize() {
        return 16;   // bytes
    }

    @Override
    protected byte[] doChecksumWithKey(byte[] data, int start, int len,
                                       byte[] key, int usage) throws KrbException {
        byte[] Ksign = key;

        byte[] salt = Rc4.getSalt(usage, false);

        hashProvider().hash(salt);
        hashProvider().hash(data, start, len);
        byte[] hashTmp = hashProvider().output();

        return Hmac.hmac(hashProvider(), Ksign, hashTmp);
    }
}
