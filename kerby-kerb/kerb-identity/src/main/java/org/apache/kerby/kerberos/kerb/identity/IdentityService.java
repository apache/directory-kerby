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
package org.apache.kerby.kerberos.kerb.identity;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.ticket.EncTicketPart;

/**
 * Identity service for KDC backend to create, get and manage principal accounts.
 */
public interface IdentityService {

    /**
     * Query to know if xtrans is supported or not.
     * @return true if supported, false otherwise
     */
    boolean supportBatchTrans();

    /**
     * Start a transaction.
     * @return xtrans
     */
    BatchTrans startBatchTrans() throws KrbException;

    /**
     * Get all of the identity principal names.
     * Note it's ordered by principal name.
     * @return principal names
     * @throws KrbException e
     */
    Iterable<String> getIdentities() throws KrbException;

    /**
     * Get the identity account specified by name.
     * @param principalName The principal name
     * @return identity
     * @throws KrbException e
     */
    KrbIdentity getIdentity(String principalName) throws KrbException;

    /**
     * Get an identity's Authorization Data.
     * @param kdcRequest The KdcRequest
     * @param encTicketPart The EncTicketPart being built for the KrbIdentity
     * @return The Authorization Data
     * @throws KrbException e
     */
    AuthorizationData getIdentityAuthorizationData(Object kdcRequest,
            EncTicketPart encTicketPart) throws KrbException;

    /**
     * Add an identity, and return the newly created result.
     * @param identity The identity
     * @return identity
     * @throws KrbException e
     */
    KrbIdentity addIdentity(KrbIdentity identity) throws KrbException;

    /**
     * Update an identity, and return the updated result.
     * @param identity The identity
     * @return identity
     * @throws KrbException e
     */
    KrbIdentity updateIdentity(KrbIdentity identity) throws KrbException;

    /**
     * Delete the identity specified by principal name
     * @param principalName The principal name
     * @throws KrbException e
     */
    void deleteIdentity(String principalName) throws KrbException;
}
