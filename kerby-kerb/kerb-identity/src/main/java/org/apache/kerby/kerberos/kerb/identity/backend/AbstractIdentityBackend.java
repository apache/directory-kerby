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

import org.apache.kerby.config.Configured;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An abstract identity backend that provides default behaviors and a cache
 * with FIFO and size limit. Note only limited recently active identities are
 * kept in the cache, and other identities are meant to be loaded from
 * persistent storage by specific backend, like memory, file, SQL DB, LDAP,
 * and etc.
 */
public abstract class AbstractIdentityBackend
        extends Configured implements IdentityBackend {

    private static Logger logger =
            LoggerFactory.getLogger(AbstractIdentityBackend.class);

    /**
     * Get the Backend Config.
     */
    protected BackendConfig getBackendConfig() {
        return (BackendConfig) getConfig();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void initialize() throws KrbException {
        logger.debug("initialize called");
        doInitialize();
    }

    /**
     * Perform the real initialization work for the backend.
     */
    protected void doInitialize() throws KrbException { }

    /**
     * {@inheritDoc}
     */
    @Override
    public void start() {
        doStart();
        logger.debug("start called");
    }

    /**
     * Perform the real start work for the backend.
     */
    protected void doStart() { }

    /**
     * {@inheritDoc}
     */
    @Override
    public void stop() throws KrbException {
        doStop();
        logger.debug("stop called");
    }

    /**
     * Perform the real stop work for the backend.
     */
    protected void doStop() throws KrbException { }

    /**
     * {@inheritDoc}
     */
    @Override
    public void release() {
        doRelease();
        logger.debug("release called");
    }

    /**
     * Perform the real release work for the backend.
     */
    protected void doRelease() { }

    /**
     * {@inheritDoc}
     */
    @Override
    public Iterable<String> getIdentities() throws KrbException {
        logger.debug("getIdentities called");
        return doGetIdentities();
    }

    /**
     * Perform the real work to get identities.
     */
    protected abstract Iterable<String> doGetIdentities() throws KrbException;

    /**
     * {@inheritDoc}
     */
    @Override
    public KrbIdentity getIdentity(String principalName) throws KrbException {
        if (principalName == null || principalName.isEmpty()) {
            throw new IllegalArgumentException("Invalid principal name");
        }

        logger.debug("getIdentity called, principalName = {}", principalName);

        KrbIdentity identity = doGetIdentity(principalName);
        logger.debug("getIdentity {}, principalName = {}",
                (identity != null ? "successful" : "failed"), principalName);

        return identity;
    }

    /**
     * Add an identity, invoked by addIdentity.
     * @param principalName
     */
    protected abstract KrbIdentity doGetIdentity(String principalName) throws KrbException;

    /**
     * {@inheritDoc}
     */
    @Override
    public KrbIdentity addIdentity(KrbIdentity identity) throws KrbException {
        if (identity == null) {
            throw new IllegalArgumentException("null identity to add");
        }

        KrbIdentity added = doAddIdentity(identity);
        logger.debug("addIdentity {}, principalName = {}",
                (added != null ? "successful" : "failed"), identity.getPrincipalName());

        return added;
    }

    /**
     * Add an identity, invoked by addIdentity, and return added identity.
     * @param identity
     */
    protected abstract KrbIdentity doAddIdentity(KrbIdentity identity) throws KrbException;

    /**
     * {@inheritDoc}
     */
    @Override
    public KrbIdentity updateIdentity(KrbIdentity identity) throws KrbException {
        if (identity == null) {
            throw new IllegalArgumentException("null identity to update");
        }

        KrbIdentity updated = doUpdateIdentity(identity);
        logger.debug("addIdentity {}, principalName = {}",
                (updated != null ? "successful" : "failed"), identity.getPrincipalName());

        return updated;
    }

    /**
     * Update an identity, invoked by updateIdentity, and return updated identity.
     * @param identity
     */
    protected abstract KrbIdentity doUpdateIdentity(KrbIdentity identity) throws KrbException;

    /**
     * {@inheritDoc}
     */
    @Override
    public void deleteIdentity(String principalName) throws KrbException {
        logger.debug("deleteIdentity called, principalName = {}", principalName);

        if (principalName == null) {
            throw new IllegalArgumentException("null identity to remove");
        }

        doDeleteIdentity(principalName);
    }

    /**
     * Delete an identity, invoked by deleteIndentity.
     * @param principalName
     */
    protected abstract void doDeleteIdentity(String principalName) throws KrbException;
}
