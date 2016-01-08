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
package org.apache.kerby.kerberos.kerb.client.preauth.pkinit;

import org.apache.kerby.kerberos.kerb.crypto.dh.DhGroup;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;

import javax.crypto.spec.DHParameterSpec;

/**
 * Server configuration settings.
 *
 * TODO - Whether to use user cert vs. SAN binding.
 * TODO - What trusted roots to use.
 * TODO - The minimum allowed enc_types.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class ServerConfiguration {
    /**
     * Whether or not to use Diffie-Hellman.  The alternative is the "public key"
     * method.
     */
    private boolean isDhUsed;

    /**
     * The Diffie-Hellman group to use.
     */
    private DHParameterSpec dhGroup = DhGroup.MODP_GROUP2;

    /**
     * Whether or not to reuse Diffie-Hellman keys.
     */
    private boolean isDhKeysReused;

    /**
     * The length of time Diffie-Hellman keys can be reused.
     */
    private long dhKeyExpiration = KerberosTime.DAY;

    /**
     * The length of the Diffie-Hellman nonces.
     */
    private int dhNonceLength = 32;


    /**
     * @return the isDhUsed
     */
    public boolean isDhUsed() {
        return isDhUsed;
    }


    /**
     * @param isDhUsed the isDhUsed to set
     */
    public void setDhUsed(boolean isDhUsed) {
        this.isDhUsed = isDhUsed;
    }


    /**
     * @return the dhGroup
     */
    public DHParameterSpec getDhGroup() {
        return dhGroup;
    }


    /**
     * @param dhGroup the dhGroup to set
     */
    public void setDhGroup(DHParameterSpec dhGroup) {
        this.dhGroup = dhGroup;
    }


    /**
     * @return the isDhKeysReused
     */
    public boolean isDhKeysReused() {
        return isDhKeysReused;
    }


    /**
     * @param isDhKeysReused the isDhKeysReused to set
     */
    public void setDhKeysReused(boolean isDhKeysReused) {
        this.isDhKeysReused = isDhKeysReused;
    }


    /**
     * @return the dhKeyExpiration
     */
    public long getDhKeyExpiration() {
        return dhKeyExpiration;
    }


    /**
     * @param dhKeyExpiration the dhKeyExpiration to set
     */
    public void setDhKeyExpiration(long dhKeyExpiration) {
        this.dhKeyExpiration = dhKeyExpiration;
    }


    /**
     * @return the dhNonceLength
     */
    public int getDhNonceLength() {
        return dhNonceLength;
    }


    /**
     * @param dhNonceLength the dhNonceLength to set
     */
    public void setDhNonceLength(int dhNonceLength) {
        this.dhNonceLength = dhNonceLength;
    }
}
