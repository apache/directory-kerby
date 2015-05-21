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
import java.util.List;

/**
 * A memory map based identity backend, which is purely relying on the
 * underlying cache as the storage.
 */
public class MemoryIdentityBackend extends AbstractIdentityBackend {

    public MemoryIdentityBackend() {
        setCacheSize(100000000); // Just no idea, configurable ?
    }

    @Override
    protected KrbIdentity doGetIdentity(String principalName) {
        return null;
    }

    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) {
        return identity;
    }

    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) {
        return identity;
    }

    @Override
    protected void doDeleteIdentity(String principalName) {

    }

    @Override
    public List<String> getIdentities(int start, int limit) {
        return new ArrayList<>(getCache().keySet());
    }

    @Override
    public List<String> getIdentities() {
        //TODO
        return null;
    }
}
