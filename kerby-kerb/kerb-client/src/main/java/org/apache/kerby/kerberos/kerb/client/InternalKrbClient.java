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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;

/**
 * An internal krb client interface.
 */
public interface InternalKrbClient {

    /**
     * Init with all the necessary options.
     * @param options
     */
    void init(KOptions options) throws KrbException;

    /**
     * Get krb client settings.
     * @return setting
     */
    KrbSetting getSetting();

    /**
     * Request a Ticket Granting Ticket.
     * @param requestOptions
     * @return a TGT
     * @throws KrbException
     */
    TgtTicket requestTgtTicket(KOptions requestOptions) throws KrbException;

    /**
     * Request a service ticket using a TGT.
     * @return service ticket
     * @throws KrbException
     */
    ServiceTicket requestServiceTicketWithTgt(TgtTicket tgt,
                                              String serverPrincipal) throws KrbException;

    /**
     * Request a service ticket using an Access Token.
     * @return service ticket
     * @throws KrbException
     */
    ServiceTicket requestServiceTicketWithAccessToken(AuthToken token,
                                              String serverPrincipal) throws KrbException;
}
