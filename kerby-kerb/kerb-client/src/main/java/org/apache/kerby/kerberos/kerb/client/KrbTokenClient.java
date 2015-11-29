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

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

/**
 * A krb token client API for applications to interact with KDC using token.
 */
public class KrbTokenClient {
    private final KrbClient krbClient;

    /**
     * Constructor with prepared KrbClient.
     * @param krbClient The krb client
     */
    public KrbTokenClient(KrbClient krbClient) {
        this.krbClient = krbClient;
    }

    /**
     * Get krb client.
     * @return KrbClient
     */
    public KrbClient getKrbClient() {
        return krbClient;
    }

    /**
     * Request a TGT with user token credential
     * @param token The auth token
     * @param armorCache The armor cache
     * @return TGT
     * @throws KrbException e
     */
    public TgtTicket requestTgt(AuthToken token, String armorCache) throws KrbException {
        if (!token.isIdToken()) {
            throw new IllegalArgumentException("Identity token is expected");
        }

        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.TOKEN_USER_ID_TOKEN, token);
        requestOptions.add(KrbOption.ARMOR_CACHE, armorCache);
        return krbClient.requestTgt(requestOptions);
    }

    /**
     * Request a service ticket using an Access Token.
     * @param token The auth token
     * @param serverPrincipal The server principal
     * @param armorCache The armor cache
     * @return service ticket
     * @throws KrbException e
     */
    public SgtTicket requestSgt(
        AuthToken token, String serverPrincipal, String armorCache) throws KrbException {
        if (!token.isAcToken()) {
            throw new IllegalArgumentException("Access token is expected");
        }

        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.TOKEN_USER_AC_TOKEN, token);
        requestOptions.add(KrbOption.ARMOR_CACHE, armorCache);
        requestOptions.add(KrbOption.SERVER_PRINCIPAL, serverPrincipal);

        return krbClient.requestSgt(requestOptions);
    }
}
