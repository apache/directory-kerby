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

import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.kerby.config.Conf;
import org.apache.kerby.kerberos.kdc.identitybackend.LdapIdentityBackend;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(FrameworkRunner.class)
@CreateDS(name = "KerberosKRBProtocolTest-class",
        partitions =
                {
                        @CreatePartition(
                                name = "example",
                                suffix = "dc=example,dc=com")
                })
@CreateLdapServer(
        transports =
                {
                        @CreateTransport(protocol = "LDAP")
                })
@ApplyLdifs(
        {
                "dn: dc=example,dc=com",
                "objectClass: top",
                "objectClass: domain",
                "dc: example",
                "dn: ou=users,dc=example,dc=com",
                "objectClass: top",
                "objectClass: organizationalUnit",
                "ou: users"
        }
)
public class LdapIdentityBackendTest extends AbstractLdapIdentityBackendTest
{
    private LdapIdentityBackend backend;

    @Test
    public void setUp() throws Exception
    {
        Conf config = new Conf();
        config.setInt("port", getLdapServer().getPort());
        this.backend = new LdapIdentityBackend(config);
        backend.initialize();
        backend.start();
    }

    @After
    public void tearDown() throws Exception
    {
        backend.stop();
        backend.release();
    }
}