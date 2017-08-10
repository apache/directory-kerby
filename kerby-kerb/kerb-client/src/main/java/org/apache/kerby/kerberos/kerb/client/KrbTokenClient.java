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
import org.apache.kerby.kerberos.kerb.type.base.KrbToken;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

import java.io.File;

/**
 * A krb token client API for applications to interact with KDC using token.
 */
public class KrbTokenClient extends KrbClientBase {

    /**
     * Default constructor.
     * @throws KrbException e
     */
    public KrbTokenClient() throws KrbException {
        super();
    }

    /**
     * Construct with prepared KrbConfig.
     * @param krbConfig The krb config
     */
    public KrbTokenClient(KrbConfig krbConfig) {
        super(krbConfig);
    }

    /**
     * Constructor with conf dir
     * @param confDir The conf dir
     * @throws KrbException e
     */
    public KrbTokenClient(File confDir) throws KrbException {
        super(confDir);
    }

    /**
     * Constructor with prepared KrbClient.
     * @param krbClient The krb client
     */
    public KrbTokenClient(KrbClient krbClient) {
        super(krbClient);
    }

    /**
     * Request a TGT with user token credential and armor cache
     * @param token The KrbToken
     * @param armorCache The armor cache
     * @return TGT
     * @throws KrbException e
     */
    public TgtTicket requestTgt(KrbToken token, String armorCache) throws KrbException {
        if (!token.isIdToken()) {
            throw new IllegalArgumentException("Identity token is expected");
        }

        KOptions requestOptions = new KOptions();
        requestOptions.add(TokenOption.USER_ID_TOKEN, token);
        requestOptions.add(KrbOption.ARMOR_CACHE, armorCache);
        return requestTgt(requestOptions);
    }

    /**
     * Request a TGT with user token credential and tgt
     * @param token The KrbToken
     * @param tgt The tgt ticket
     * @return TGT
     * @throws KrbException e
     */
    public TgtTicket requestTgt(KrbToken token, TgtTicket tgt) throws KrbException {
        if (!token.isIdToken()) {
            throw new IllegalArgumentException("Identity token is expected");
        }

        KOptions requestOptions = new KOptions();
        requestOptions.add(TokenOption.USER_ID_TOKEN, token);
        requestOptions.add(KrbOption.TGT, tgt);
        return requestTgt(requestOptions);
    }

    /**
     * Request a service ticket using an Access Token.
     * @param token The KrbToken
     * @param serverPrincipal The server principal
     * @param armorCache The armor cache
     * @return service ticket
     * @throws KrbException e
     */
    public SgtTicket requestSgt(
        KrbToken token, String serverPrincipal, String armorCache) throws KrbException {
        if (!token.isAcToken()) {
            throw new IllegalArgumentException("Access token is expected");
        }

        KOptions requestOptions = new KOptions();
        requestOptions.add(TokenOption.USER_AC_TOKEN, token);
        requestOptions.add(KrbOption.ARMOR_CACHE, armorCache);
        requestOptions.add(KrbOption.SERVER_PRINCIPAL, serverPrincipal);

        return requestSgt(requestOptions);
    }

    public SgtTicket requestSgt(KrbToken token, String serverPrincipal, TgtTicket tgt) throws KrbException {
        if (!token.isAcToken()) {
            throw new IllegalArgumentException("Access token is expected");
        }

        KOptions requestOptions = new KOptions();
        requestOptions.add(TokenOption.USER_AC_TOKEN, token);
        requestOptions.add(KrbOption.TGT, tgt);
        requestOptions.add(KrbOption.SERVER_PRINCIPAL, serverPrincipal);

        return requestSgt(requestOptions);
    }
}
