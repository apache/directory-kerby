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

import org.apache.kerby.kerberos.kerb.crypto.enc.provider.Des3Provider;
import org.apache.kerby.kerberos.kerb.crypto.key.Des3KeyMaker;
import org.apache.kerby.kerberos.kerb.spec.common.CheckSumType;

public class HmacSha1Des3CheckSum extends HmacKcCheckSum {

    public HmacSha1Des3CheckSum() {
        super(new Des3Provider(), 20, 20);

        keyMaker(new Des3KeyMaker(encProvider()));
    }

    public int confounderSize() {
        return 8;
    }

    public CheckSumType cksumType() {
        return CheckSumType.HMAC_SHA1_DES3;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 20;  // bytes
    }

    public int keySize() {
        return 24;   // bytes
    }
}
