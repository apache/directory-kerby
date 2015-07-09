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
package org.apache.kerby.kerberos.kdc;

import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.ldap.LdapServer;

public class AbstractLdapBackendKdcTest extends KerbyKdcTest {

    /** The used DirectoryService instance */
    private static DirectoryService service;

    /** The used LdapServer instance */
    private static LdapServer ldapServer;

    public static DirectoryService getService() {
        return service;
    }


    public static void setService(DirectoryService service) {
        AbstractLdapBackendKdcTest.service = service;
    }


    public static LdapServer getLdapServer() {
        return ldapServer;
    }

    public static void setLdapServer(LdapServer ldapServer) {
        AbstractLdapBackendKdcTest.ldapServer = ldapServer;
    }
}
