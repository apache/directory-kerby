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
package org.apache.kerby.kerberos.kerb.identity.backend;

import org.apache.kerby.config.Configurable;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.IdentityService;

/**
 * Identity backend for KDC, either internal embedded or external standalone.
 */
public interface IdentityBackend extends IdentityService, Configurable {

    /**
     * Init work for the backend can be done here.
     * @throws KrbException e
     */
    void initialize() throws KrbException;

    /**
     * Start the backend and return soon after the backend or the connection to
     * it is well prepared and ready for KDC to use.
     *
     * Will be called during KDC startup.
     */
    void start();

    /**
     * Stop the backend.
     *
     * Will be called during KDC stop.
     * @throws KrbException e
     */
    void stop() throws KrbException;

    /**
     * Release the backend associated resources like connection.
     *
     * Will be called during KDC shutdown.
     */
    void release();
}
