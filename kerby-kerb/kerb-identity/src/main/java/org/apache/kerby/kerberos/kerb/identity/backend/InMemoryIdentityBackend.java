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

import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class InMemoryIdentityBackend extends AbstractIdentityBackend {

    private Map<String, KrbIdentity> identities;

    public InMemoryIdentityBackend() {
        this.identities = new HashMap<String, KrbIdentity>();
    }

    public InMemoryIdentityBackend(Map<String, KrbIdentity> identities) {
        this();
        this.identities.putAll(identities);
    }

    @Override
    public List<KrbIdentity> getIdentities() {
        List<KrbIdentity> results = new ArrayList<KrbIdentity>(identities.size());
        results.addAll(identities.values());
        return results;
    }

    @Override
    public boolean checkIdentity(String name) {
        return identities.containsKey(name);
    }

    @Override
    public KrbIdentity getIdentity(String name) {
        if (identities.containsKey(name)) {
            return identities.get(name);
        }
        return null;
    }

    @Override
    public void addIdentity(KrbIdentity identity) {
        identities.put(identity.getPrincipalName(), identity);
    }

    @Override
    public void updateIdentity(KrbIdentity identity) {
        identities.put(identity.getPrincipalName(), identity);
    }

    @Override
    public void deleteIdentity(KrbIdentity identity) {
        identities.remove(identity.getPrincipalName());
    }
}
