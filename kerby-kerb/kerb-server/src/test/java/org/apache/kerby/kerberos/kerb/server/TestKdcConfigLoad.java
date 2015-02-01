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
package org.apache.kerby.kerberos.kerb.server;

import org.apache.kerby.config.Conf;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

import static org.assertj.core.api.Assertions.assertThat;

public class TestKdcConfigLoad {

    @Test
    public void test() throws URISyntaxException, IOException {
        URL confFileUrl = TestKdcConfigLoad.class.getResource("/kdc.conf");
        File confFile = new File(confFileUrl.toURI());

        KdcConfig krbConfig = new KdcConfig();
        Conf conf = krbConfig.getConf();
        conf.addIniConfig(confFile);

        assertThat(krbConfig.getDefaultLoggingLocation()).isEqualTo("FILE:/var/log/krb5libs.log");
        assertThat(krbConfig.getKdcLoggingLocation()).isEqualTo("FILE:/var/log/krb5kdc.log");
        assertThat(krbConfig.getAdminLoggingLocation()).isEqualTo("FILE:/var/log/kadmind.log");

        assertThat(krbConfig.getKdcUdpPort()).isEqualTo((short)88);
        assertThat(krbConfig.getKdcTcpPort()).isEqualTo((short)8014);
        assertThat(krbConfig.isRestrictAnonymousToTgt()).isTrue();
        assertThat(krbConfig.getKdcMaxDgramReplySize()).isEqualTo(4096);

        /* will be moved to LdapLdentityBackend module
        String[] ldapContainerDn = krbConfig.getLdapKerberosContainerDn();
        assertThat(ldapContainerDn.length).isEqualTo(3);
        assertThat(ldapContainerDn[0]).isEqualTo("cn=krbcontainer");
        assertThat(ldapContainerDn[1]).isEqualTo("dc=mit");
        assertThat(ldapContainerDn[2]).isEqualTo("dc=edu");
        */
    }
}
