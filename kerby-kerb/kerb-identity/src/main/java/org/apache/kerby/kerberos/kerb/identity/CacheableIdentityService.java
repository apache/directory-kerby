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

import org.apache.kerby.config.Config;
import org.apache.kerby.config.Configured;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.ticket.EncTicketPart;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A cacheable identity backend that provides a cache with FIFO and size limit.
 * Note only limited recently active identities are kept in the cache, and other
 * identities are meant to be loaded from the underlying backend like memory,
 * file, SQL DB, LDAP, and etc.
 */
public class CacheableIdentityService
        extends Configured implements IdentityService {

    private static final int DEFAULT_CACHE_SIZE = 1000;

    private Map<String, KrbIdentity> idCache;
    private int cacheSize = DEFAULT_CACHE_SIZE;

    private IdentityService underlying;

    public CacheableIdentityService(Config config, IdentityService underlying) {
        super(config);
        this.underlying = underlying;

        init();
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

    private void init() {
        Map<String, KrbIdentity> tmpMap =
            new LinkedHashMap<String, KrbIdentity>(cacheSize) {
                private static final long serialVersionUID = -6911200685333503214L;

                @Override
                protected boolean removeEldestEntry(Map.Entry<String, KrbIdentity> eldest) {
                    return size() > cacheSize;
                }
            };

        idCache = new ConcurrentHashMap<>(tmpMap);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Iterable<String> getIdentities() throws KrbException {
        return underlying.getIdentities();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KrbIdentity getIdentity(String principalName) throws KrbException {
        if (idCache.containsKey(principalName)) {
            return idCache.get(principalName);
        }

        KrbIdentity identity = underlying.getIdentity(principalName);
        if (identity != null) {
            idCache.put(principalName, identity);
        }

        return identity;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KrbIdentity addIdentity(KrbIdentity identity) throws KrbException {
        KrbIdentity added = underlying.addIdentity(identity);
        if (added != null) {
            idCache.put(added.getPrincipalName(), added);
        }

        return added;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KrbIdentity updateIdentity(KrbIdentity identity) throws KrbException {
        KrbIdentity updated = underlying.updateIdentity(identity);
        if (updated != null) {
            idCache.put(updated.getPrincipalName(), updated);
        }

        return updated;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void deleteIdentity(String principalName) throws KrbException {
        if (idCache.containsKey(principalName)) {
            idCache.remove(principalName);
        }

        underlying.deleteIdentity(principalName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthorizationData getIdentityAuthorizationData(Object kdcRequest,
            EncTicketPart encTicketPart) throws KrbException {

        return underlying.getIdentityAuthorizationData(kdcRequest,
                encTicketPart);
    }
}
