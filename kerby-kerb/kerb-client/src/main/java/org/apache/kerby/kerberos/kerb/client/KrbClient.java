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
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

import java.io.File;

/**
 * A Krb client API for applications to interact with KDC
 */
public class KrbClient extends KrbClientBase {

    /**
     * Default constructor.
     * @throws KrbException e
     */
    public KrbClient() throws KrbException {
        super();
    }

    /**
     * Construct with prepared KrbConfig.
     * @param krbConfig The krb config
     */
    public KrbClient(KrbConfig krbConfig) {
        super(krbConfig);
    }

    /**
     * Constructor with conf dir
     * @param confDir The conf dir
     * @throws KrbException e
     */
    public KrbClient(File confDir) throws KrbException {
        super(confDir);
    }

    /**
     * Request a TGT with user plain credential
     * @param principal The principal
     * @param password The password
     * @return The tgt ticket
     * @throws KrbException e
     */
    public TgtTicket requestTgt(String principal,
                                String password) throws KrbException {
        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.CLIENT_PRINCIPAL, principal);
        requestOptions.add(KrbOption.USE_PASSWD, true);
        requestOptions.add(KrbOption.USER_PASSWD, password);
        return requestTgt(requestOptions);
    }

    /**
     * Request a TGT with user plain credential
     * @param principal The principal
     * @param keytabFile The keytab file
     * @return TGT
     * @throws KrbException e
     */
    public TgtTicket requestTgt(String principal,
                                File keytabFile) throws KrbException {
        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.CLIENT_PRINCIPAL, principal);
        requestOptions.add(KrbOption.USE_KEYTAB, true);
        requestOptions.add(KrbOption.KEYTAB_FILE, keytabFile);
        return requestTgt(requestOptions);
    }
}
