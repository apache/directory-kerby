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
package org.apache.kerby.kerberos.kerb.client.impl;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbSetting;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;

/**
 * An internal krb client interface.
 */
public interface InternalKrbClient {

    /**
     * Init with all the necessary options.
     * @throws KrbException e
     */
    void init() throws KrbException;

    /**
     * Get krb client settings.
     * @return setting
     */
    KrbSetting getSetting();

    /**
     * Request a Ticket Granting Ticket.
     * @param requestOptions The request options
     * @return a TGT
     * @throws KrbException e
     */
    TgtTicket requestTgtTicket(KOptions requestOptions) throws KrbException;

    /**
     * Request a service ticket.
     * @param requestOptions The request options
     * @return service ticket
     * @throws KrbException e
     */
    ServiceTicket requestServiceTicket(KOptions requestOptions) throws KrbException;
}
