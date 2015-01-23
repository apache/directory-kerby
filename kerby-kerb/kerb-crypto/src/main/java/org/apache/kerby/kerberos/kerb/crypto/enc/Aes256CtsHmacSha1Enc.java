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
package org.apache.kerby.kerberos.kerb.crypto.enc;

import org.apache.kerby.kerberos.kerb.crypto.cksum.provider.Sha1Provider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.Aes256Provider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.AesProvider;
import org.apache.kerby.kerberos.kerb.crypto.key.AesKeyMaker;
import org.apache.kerby.kerberos.kerb.spec.common.CheckSumType;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;

public class Aes256CtsHmacSha1Enc extends KeKiHmacSha1Enc {

    public Aes256CtsHmacSha1Enc() {
        super(new Aes256Provider(), new Sha1Provider());
        keyMaker(new AesKeyMaker((AesProvider) encProvider()));
    }

    public EncryptionType eType() {
        return EncryptionType.AES256_CTS_HMAC_SHA1_96;
    }

    public CheckSumType checksumType() {
        return CheckSumType.HMAC_SHA1_96_AES256;
    }

    @Override
    public int checksumSize() {
        return 96 / 8;
    }
}
