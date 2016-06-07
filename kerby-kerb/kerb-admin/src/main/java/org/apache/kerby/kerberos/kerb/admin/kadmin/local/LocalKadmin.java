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
package org.apache.kerby.kerberos.kerb.admin.kadmin.local;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.Kadmin;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;

/**
 * Server side admin facilities for local, similar to MIT kadmin local mode. It
 * may be not accurate regarding 'local' because, if the identity backend itself
 * is supported to be accessed from remote, it won't have to be remote; but if
 * not, then it must be local to the KDC admin bounded with the local backend.
 *
 * Note, suitable with Kerby AdminServerImpl based KDCs like Kerby KDC.
 */
public interface LocalKadmin extends Kadmin {

    /**
     * Check the built-in principals, will throw KrbException if not exist.
     * @throws KrbException e
     */
    void checkBuiltinPrincipals() throws KrbException;

    /**
     * Create build-in principals.
     * @throws KrbException e
     */
    void createBuiltinPrincipals() throws KrbException;

    /**
     * Delete build-in principals.
     * @throws KrbException e
     */
    void deleteBuiltinPrincipals() throws KrbException;

    /**
     * Get kdc config.
     *
     * @return The kdc config.
     */
    KdcConfig getKdcConfig();

    /**
     * Get backend config.
     *
     * @return The backend config.
     */
    BackendConfig getBackendConfig();

    /**
     * Get identity backend.
     *
     * @return IdentityBackend
     */
    IdentityBackend getIdentityBackend();

    /**
     * Get the identity from backend.
     *
     * @param principalName The principal name
     * @return identity
     * @throws KrbException e
     */
    KrbIdentity getPrincipal(String principalName) throws KrbException;

    int size() throws KrbException;
}
