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
package org.apache.kerby.kerberos.kerb.client;

import org.apache.kerby.kerberos.kerb.client.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.crypto.util.Nonce;

public class KrbContext {

    private KrbSetting krbSetting;
    private PreauthHandler preauthHandler;

    /**
     * Init with krbsetting.
     * @param krbSetting The krb setting
     */
    public void init(KrbSetting krbSetting) {
        this.krbSetting = krbSetting;
        preauthHandler = new PreauthHandler();
        preauthHandler.init(this);
    }

    /**
     * Get krbsetting.
     * @return The krb setting
     */
    public KrbSetting getKrbSetting() {
        return krbSetting;
    }

    /**
     * Get krbconfig.
     * @return The krb config
     */
    public KrbConfig getConfig() {
        return krbSetting.getKrbConfig();
    }

    /**
     * Generate nonce.
     * @return nonce
     */
    public int generateNonce() {
        return Nonce.value();
    }

    /**
     * Get ticket valid time.
     * @return The ticket valid time
     */
    public long getTicketValidTime() {
        return 8 * 60 * 60 * 1000;
    }

    /**
     * Get preauth handler.
     * @return The preauth handler
     */
    public PreauthHandler getPreauthHandler() {
        return preauthHandler;
    }
}
