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
package org.apache.kerby.kerberos.kerb.client.request;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.client.KOptions;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.crypto.fast.FastArmor;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;

import java.io.File;
import java.io.IOException;

/**
 * This initiates an armor protected AS-REQ using FAST/Pre-auth.
 */
public abstract class ArmoredAsRequest extends AsRequest {

    public ArmoredAsRequest(KrbContext context) {
        super(context);
    }

    @Override
    public KOptions getPreauthOptions() {
        KOptions results = new KOptions();

        KOptions krbOptions = getKrbOptions();
        results.add(krbOptions.getOption(KrbOption.ARMOR_CACHE));

        return results;
    }

    /**
     * Prepare FAST armor key.
     * @return
     * @throws KrbException
     */
    protected EncryptionKey makeArmorKey() throws KrbException {
        EncryptionKey subKey = null;
        EncryptionKey armorCacheKey = getArmorCacheKey();
        EncryptionKey armorKey = FastArmor.cf2(subKey, "subkeyarmor",
                armorCacheKey, "ticketarmor");

        return armorKey;
    }

    /**
     * Get armor cache key.
     * @return armor cache key
     * @throws KrbException
     */
    protected EncryptionKey getArmorCacheKey() throws KrbException {
        KOptions preauthOptions = getPreauthOptions();
        String ccache = preauthOptions.getStringOption(KrbOption.KRB5_CACHE);
        File ccacheFile = new File(ccache);
        CredentialCache cc = null;
        try {
            cc = resolveCredCache(ccacheFile);
        } catch (IOException e) {
            throw new KrbException("Failed to load armor cache file");
        }
        EncryptionKey armorCacheKey =
                cc.getCredentials().iterator().next().getKey();;

        return armorCacheKey;
    }
}
