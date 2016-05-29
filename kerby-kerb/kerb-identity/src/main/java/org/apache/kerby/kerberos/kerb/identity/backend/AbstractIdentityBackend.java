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
import org.apache.kerby.kerberos.kerb.identity.BatchTrans;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.ticket.EncTicketPart;
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
     * @return The backend config
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
     * {@inheritDoc}
     */
    @Override
    public boolean supportBatchTrans() {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public BatchTrans startBatchTrans() throws KrbException {
        throw new KrbException("Transaction isn't supported");
    }

    /**
     * Perform the real initialization work for the backend.
     * @throws KrbException e
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
     * @throws KrbException e
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
     * @return The identities
     * @throws KrbException e
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
     * @param principalName The principal name
     * @return The added identity
     * @throws  KrbException e
     */
    protected abstract KrbIdentity doGetIdentity(String principalName) throws KrbException;

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthorizationData getIdentityAuthorizationData(Object kdcRequest,
            EncTicketPart encTicketPart) throws KrbException {
        if (kdcRequest == null) {
            throw new IllegalArgumentException("Invalid identity");
        }

        logger.debug("getIdentityAuthorizationData called, krbIdentity = {}",
                kdcRequest);

        AuthorizationData authData = doGetIdentityAuthorizationData(kdcRequest,
                encTicketPart);
        logger.debug("getIdentityAuthorizationData {}, authData = {}",
                (authData != null ? "successful" : "failed"), authData);

        return authData;
    }

    /**
     * Get an identity's Authorization Data, invoked by getIdentityAuthorizationData.
     * @param krbIdentity The KrbIdentity
     * @param encTicketPart The EncTicketPart being built for the KrbIdentity
     * @return The Authorization Data
     * @throws KrbException e
     */
    protected AuthorizationData doGetIdentityAuthorizationData(
            Object kdcRequest, EncTicketPart encTicketPart)
            throws KrbException {
        return null;
    }

    /** {@inheritDoc} */
    @Override
    public KrbIdentity addIdentity(KrbIdentity identity) throws KrbException {
        if (identity == null) {
            throw new IllegalArgumentException("null identity to add");
        }
        if (doGetIdentity(identity.getPrincipalName()) != null) {
            throw new KrbException("Principal already exists: "
                    + identity.getPrincipalName());
        }

        KrbIdentity added = doAddIdentity(identity);
        logger.debug("addIdentity {}, principalName = {}",
                (added != null ? "successful" : "failed"), identity.getPrincipalName());

        return added;
    }

    /**
     * Add an identity, invoked by addIdentity, and return added identity.
     * @param identity The identity to be added
     * @return The added identity
     * @throws KrbException e
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

        if (doGetIdentity(identity.getPrincipalName()) == null) {
            logger.error("Error occurred while updating identity, principal "
                + identity.getPrincipalName() + " does not exists.");
            throw new KrbException("Principal does not exist.");
        }

        KrbIdentity updated = doUpdateIdentity(identity);
        logger.debug("updateIdentity {}, principalName = {}",
                (updated != null ? "successful" : "failed"), identity.getPrincipalName());

        return updated;
    }

    /**
     * Update an identity, invoked by updateIdentity, and return updated identity.
     * @param identity The origin identity
     * @return The updated identity
     * @throws KrbException e
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

        if (doGetIdentity(principalName) == null) {
            logger.error("Error occurred while deleting identity, principal "
                    + principalName + " does not exists.");
            throw new KrbException("Principal does not exist.");
        }

        doDeleteIdentity(principalName);
    }

    /**
     * Delete an identity, invoked by deleteIndentity.
     * @param principalName The principal name
     * @throws KrbException e
     */
    protected abstract void doDeleteIdentity(String principalName) throws KrbException;
}
