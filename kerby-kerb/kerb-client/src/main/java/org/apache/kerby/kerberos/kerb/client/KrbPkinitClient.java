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
import org.apache.kerby.kerberos.kerb.KrbConstant;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

import java.io.File;

/**
 * A krb PKINIT client API for applications to interact with KDC using PKINIT.
 */
public class KrbPkinitClient extends KrbClientBase {

    /**
     * Default constructor.
     * @throws KrbException e
     */
    public KrbPkinitClient() throws KrbException {
        super();
    }

    /**
     * Construct with prepared KrbConfig.
     * @param krbConfig The krb config
     */
    public KrbPkinitClient(KrbConfig krbConfig) {
        super(krbConfig);
    }

    /**
     * Constructor with conf dir
     * @param confDir The conf dir
     * @throws KrbException e
     */
    public KrbPkinitClient(File confDir) throws KrbException {
        super(confDir);
    }

    /**
     * Constructor with prepared KrbClient.
     * @param krbClient The krb client
     */
    public KrbPkinitClient(KrbClient krbClient) {
        super(krbClient);
    }

    /**
     * Request a TGT with user x509 certificate credential
     * @param principal The principal
     * @param certificate The certificate
     * @param privateKey The private key
     * @return TGT
     * @throws KrbException e
     */
    public TgtTicket requestTgt(String principal, String certificate,
                                String privateKey) throws KrbException {
        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.CLIENT_PRINCIPAL, principal);
        requestOptions.add(PkinitOption.USE_PKINIT);
        requestOptions.add(PkinitOption.USING_RSA);
        requestOptions.add(PkinitOption.X509_IDENTITY, certificate);
        requestOptions.add(PkinitOption.X509_PRIVATE_KEY, privateKey);
        return requestTgt(requestOptions);
    }

    /**
     * Request a TGT with using Anonymous PKINIT
     * @return TGT
     * @throws KrbException e
     */
    public TgtTicket requestTgt() throws KrbException {
        KOptions requestOptions = new KOptions();
        requestOptions.add(PkinitOption.USE_ANONYMOUS);
        requestOptions.add(KrbOption.CLIENT_PRINCIPAL,
            KrbConstant.ANONYMOUS_PRINCIPAL);
        return requestTgt(requestOptions);
    }
}
