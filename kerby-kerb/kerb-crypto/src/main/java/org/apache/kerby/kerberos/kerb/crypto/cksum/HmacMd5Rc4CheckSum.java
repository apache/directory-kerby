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

import org.apache.kerby.kerberos.kerb.crypto.Hmac;
import org.apache.kerby.kerberos.kerb.crypto.Rc4;
import org.apache.kerby.kerberos.kerb.crypto.cksum.provider.Md5Provider;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.common.CheckSumType;

public class HmacMd5Rc4CheckSum extends AbstractKeyedCheckSumTypeHandler {

    public HmacMd5Rc4CheckSum() {
        super(null, new Md5Provider(), 16, 16);
    }

    public int confounderSize() {
        return 8;
    }

    public CheckSumType cksumType() {
        return CheckSumType.HMAC_MD5_ARCFOUR;
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

        byte[] Ksign = null;
        byte[] signKey = "signaturekey".getBytes();
        byte[] newSignKey = new byte[signKey.length + 1];
        System.arraycopy(signKey, 0, newSignKey, 0, signKey.length);
        Ksign = Hmac.hmac(hashProvider(), key, newSignKey);

        byte[] salt = Rc4.getSalt(usage, false);

        hashProvider().hash(salt);
        hashProvider().hash(data, start, len);
        byte[] hashTmp = hashProvider().output();

        byte[] hmac = Hmac.hmac(hashProvider(), Ksign, hashTmp);
        return hmac;
    }
}
