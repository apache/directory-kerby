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

import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.kerby.kerberos.kdc.identitybackend.LdapIdentityBackend;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

public abstract class AbstractLdapIdentityBackendTest extends AbstractLdapTestUnit {
    protected LdapIdentityBackend backend;

    /** The used DirectoryService instance */
    private static DirectoryService service;

    public static DirectoryService getDirectoryService() {
        return service;
    }

    public static void setDirectoryService(DirectoryService service) {
        AbstractLdapIdentityBackendTest.service = service;
    }

    private BackendTest test = new LdapBackendTest();

    @AfterEach
    public void tearDown() throws Exception {
        backend.stop();
        backend.release();
    }

    @Test
    public void testGet() throws KrbException {
        test.testGet(backend);
    }

    @Test
    public void testStore() throws KrbException {
        test.testStore(backend);
    }

    @Test
    public void testUpdate() throws KrbException {
        test.testUpdate(backend);
    }

    @Test
    public void testDelete() throws KrbException {
        test.testDelete(backend);
    }

    @Test
    public void testGetIdentities() throws KrbException {
        test.testGetIdentities(backend);
    }

    private static class LdapBackendTest extends BackendTest {

    }
}
