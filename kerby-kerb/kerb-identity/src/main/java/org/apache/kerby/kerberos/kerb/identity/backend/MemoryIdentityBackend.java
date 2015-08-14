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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A memory map based identity backend.
 */
public class MemoryIdentityBackend extends AbstractIdentityBackend {
    // TODO: configurable
    private static final int DEFAULT_STORAGE_SIZE = 10000000;

    private Map<String, KrbIdentity> storage;
    private int storageSize = DEFAULT_STORAGE_SIZE;

    protected void doInitialize() {
        Map<String, KrbIdentity> tmpMap =
            new LinkedHashMap<String, KrbIdentity>(storageSize) {
                private static final long serialVersionUID = 714064587685837472L;

                @Override
                protected boolean removeEldestEntry(Map.Entry<String, KrbIdentity> eldest) {
                    return size() > storageSize;
                }
            };

        storage = new ConcurrentHashMap<>(tmpMap);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doGetIdentity(String principalName) {
        return storage.get(principalName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) {
        return storage.put(identity.getPrincipalName(), identity);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) {
        return storage.put(identity.getPrincipalName(), identity);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doDeleteIdentity(String principalName) {
        storage.remove(principalName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Iterable<String> doGetIdentities() throws KrbException {
        List<String> identities = new ArrayList<>(storage.keySet());
        Collections.sort(identities);
        return identities;
    }
}
