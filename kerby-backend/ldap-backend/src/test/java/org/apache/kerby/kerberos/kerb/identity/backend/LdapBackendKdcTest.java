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
import org.apache.directory.server.core.integ.ApacheDSTestExtension;
import org.apache.kerby.config.Conf;
import org.apache.kerby.kerberos.kdc.identitybackend.LdapIdentityBackend;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith({ ApacheDSTestExtension.class })
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
                        @CreateTransport(protocol = "LDAP", address = "127.0.0.1")
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
public class LdapBackendKdcTest extends AbstractLdapBackendKdcTest {
    private LdapIdentityBackend backend;

    @BeforeEach
    public void startUp() throws Exception {
        Conf config = new Conf();
        config.setString("host", "127.0.0.1");
        config.setString("admin_dn", ADMIN_DN);
        config.setString("admin_pw", ADMIN_PW);
        config.setString("base_dn", BASE_DN);
        int port = getLdapServer().getPort();
        config.setInt("port", port);
        test.setPort(port);
        this.backend = new LdapIdentityBackend(config);
        backend.initialize();
        backend.start();
        test.createTestDir();
        test.setUp();
    }

    @AfterEach
    public void tearDown() throws Exception {
        backend.stop();
        backend.release();
        test.deleteTestDir();
    }

    @Test
    public void testKdc() throws Exception {
        TgtTicket tgt;
        SgtTicket tkt;

        try {
            tgt = test.getKrbClient().requestTgt(
                    test.getClientPrincipal(), test.getClientPassword());
            assertThat(tgt).isNotNull();

            tkt = test.getKrbClient().requestSgt(tgt, test.getServerPrincipal());
            assertThat(tkt).isNotNull();
        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail("Exception occurred with good password. "
                    + e.toString());
        }
    }
}
