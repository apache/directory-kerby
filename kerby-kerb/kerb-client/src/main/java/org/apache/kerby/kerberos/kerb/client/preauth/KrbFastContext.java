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
package org.apache.kerby.kerberos.kerb.client.preauth;

import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.fast.FastOptions;
import org.apache.kerby.kerberos.kerb.spec.fast.KrbFastArmor;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReq;

/**
 * Maintaining FAST processing state in client side per request.
 */
public class KrbFastContext {

    private KdcReq fastOuterRequest;
    private EncryptionKey armorKey;
    private KrbFastArmor fastArmor;
    private FastOptions fastOptions;
    private int nonce;
    private int fastFlags;

    public KdcReq getFastOuterRequest() {
        return fastOuterRequest;
    }

    public void setFastOuterRequest(KdcReq fastOuterRequest) {
        this.fastOuterRequest = fastOuterRequest;
    }

    public EncryptionKey getArmorKey() {
        return armorKey;
    }

    public void setArmorKey(EncryptionKey armorKey) {
        this.armorKey = armorKey;
    }

    public KrbFastArmor getFastArmor() {
        return fastArmor;
    }

    public void setFastArmor(KrbFastArmor fastArmor) {
        this.fastArmor = fastArmor;
    }

    public FastOptions getFastOptions() {
        return fastOptions;
    }

    public void setFastOptions(FastOptions fastOptions) {
        this.fastOptions = fastOptions;
    }

    public int getNonce() {
        return nonce;
    }

    public void setNonce(int nonce) {
        this.nonce = nonce;
    }

    public int getFastFlags() {
        return fastFlags;
    }

    public void setFastFlags(int fastFlags) {
        this.fastFlags = fastFlags;
    }
}
