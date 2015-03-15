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
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An abstract identity backend that provides default behaviors and a cache
 * with FIFO and size limit. Note only limited recently active identities are
 * kept in the cache, and other identities are meant to be loaded from
 * persistent storage by specific backend, like memory, file, SQL DB, LDAP,
 * and etc.
 */
public abstract class AbstractIdentityBackend
        extends Configured implements IdentityBackend {

    private static final int DEFAULT_CACHE_SIZE = 1000;

    private Map<String, KrbIdentity> idCache;
    private int cacheSize = DEFAULT_CACHE_SIZE;

    protected void setCacheSize(int cacheSize) {
        this.cacheSize = cacheSize;
    }

    @Override
    public void initialize() {
        idCache = new LinkedHashMap<String, KrbIdentity>(cacheSize) {
            @Override
            protected boolean removeEldestEntry(Map.Entry eldest) {
                return size() > cacheSize;
            }
        };
    }

    @Override
    public void start() {

    }

    @Override
    public void stop() {

    }

    @Override
    public void release() {
        idCache.clear();
    }

    protected Map<String, KrbIdentity> getCache() {
        return idCache;
    }

    @Override
    public KrbIdentity getIdentity(String principalName) {
        if (idCache.containsKey(principalName)) {
            return idCache.get(principalName);
        }

        KrbIdentity identity = doGetIdentity(principalName);
        if (identity != null) {
            idCache.put(principalName, identity);
        }

        return identity;
    }

    protected abstract KrbIdentity doGetIdentity(String principalName);

    @Override
    public KrbIdentity addIdentity(KrbIdentity identity) {
        KrbIdentity added = doAddIdentity(identity);
        if (added != null) {
            idCache.put(added.getPrincipalName(), added);
        }

        return added;
    }

    protected abstract KrbIdentity doAddIdentity(KrbIdentity identity);

    @Override
    public KrbIdentity updateIdentity(KrbIdentity identity) {
        KrbIdentity updated = doUpdateIdentity(identity);
        if (updated != null) {
            idCache.put(updated.getPrincipalName(), updated);
        }

        return updated;
    }

    protected abstract KrbIdentity doUpdateIdentity(KrbIdentity identity);

    @Override
    public void deleteIdentity(String principalName) {
        if (idCache.containsKey(principalName)) {
            idCache.remove(principalName);
        }
    }

}
