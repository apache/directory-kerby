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

import java.util.List;

/**
 * Identity service for KDC backend to create, get and manage principal accounts.
 */
public interface IdentityService {

    /**
     * Get the identity principal names, from start offset, with count of limit.
     * Note it's ordered by principal name.
     * @return principal names
     */
    public List<String> getIdentities(int start, int limit);

    /**
     * Get the identity account specified by name.
     * @param principalName
     * @return identity
     */
    public KrbIdentity getIdentity(String principalName);

    /**
     * Add an identity, and return the newly created result.
     * @param identity
     * @return identity
     */
    public KrbIdentity addIdentity(KrbIdentity identity);

    /**
     * Update an identity, and return the updated result.
     * @param identity
     * @return identity
     */
    public KrbIdentity updateIdentity(KrbIdentity identity);

    /**
     * Delete the identity specified by principal name
     * @param principalName
     *
     */
    public void deleteIdentity(String principalName);
}
