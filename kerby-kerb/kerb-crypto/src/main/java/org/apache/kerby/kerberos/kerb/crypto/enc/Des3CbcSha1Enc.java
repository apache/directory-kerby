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
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.Des3Provider;
import org.apache.kerby.kerberos.kerb.crypto.key.Des3KeyMaker;
import org.apache.kerby.kerberos.kerb.type.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;

public class Des3CbcSha1Enc extends KeKiHmacSha1Enc {

    public Des3CbcSha1Enc() {
        super(new Des3Provider(), new Sha1Provider(),
            new Des3KeyMaker(new Des3Provider()));
        keyMaker(new Des3KeyMaker(this.encProvider()));
    }

    @Override
    public int paddingSize() {
        return encProvider().blockSize();
    }

    public EncryptionType eType() {
        return EncryptionType.DES3_CBC_SHA1;
    }

    public CheckSumType checksumType() {
        return CheckSumType.HMAC_SHA1_DES3;
    }

}
