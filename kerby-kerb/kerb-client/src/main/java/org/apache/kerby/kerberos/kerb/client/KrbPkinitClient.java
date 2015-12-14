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

/**
 * A krb PKINIT client API for applications to interact with KDC using PKINIT.
 */
public class KrbPkinitClient {
    private final KrbClient krbClient;

    /**
     * Constructor with prepared KrbClient.
     * @param krbClient The krb client
     */
    public KrbPkinitClient(KrbClient krbClient) {
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
     * Request a TGT with user x509 certificate credential
     * @param certificate The certificate
     * @param privateKey The private key
     * @return TGT
     * @throws KrbException e
     */
    public TgtTicket requestTgt(String principal, String certificate,
                                String privateKey) throws KrbException {
        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.CLIENT_PRINCIPAL, principal);
        requestOptions.add(KrbOption.USE_PKINIT);
        requestOptions.add(KrbOption.PKINIT_USING_RSA);
        requestOptions.add(KrbOption.PKINIT_X509_IDENTITY, certificate);
        requestOptions.add(KrbOption.PKINIT_X509_PRIVATE_KEY, privateKey);
        return krbClient.requestTgt(requestOptions);
    }

    /**
     * Request a TGT with using Anonymous PKINIT
     * @return TGT
     * @throws KrbException e
     */
    public TgtTicket requestTgt(String anchors) throws KrbException {
        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.USE_PKINIT_ANONYMOUS);
        requestOptions.add(KrbOption.CLIENT_PRINCIPAL, "WELLKNOWN/ANONYMOUS");
        requestOptions.add(KrbOption.PKINIT_X509_ANCHORS, anchors);
        return krbClient.requestTgt(requestOptions);
    }
}
