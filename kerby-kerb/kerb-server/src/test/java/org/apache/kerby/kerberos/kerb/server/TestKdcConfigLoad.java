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
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

public class TestKdcConfigLoad {

    @Test
    public void test() throws URISyntaxException, IOException {
        URL confFileUrl = TestKdcConfigLoad.class.getResource("/kdc.conf");
        File confFile = new File(confFileUrl.toURI());

        KdcConfig krbConfig = new KdcConfig();
        Conf conf = krbConfig.getConf();
        conf.addIniConfig(confFile);

        Assert.assertEquals("FILE:/var/log/krb5libs.log", krbConfig.getDefaultLoggingLocation());
        Assert.assertEquals("FILE:/var/log/krb5kdc.log", krbConfig.getKdcLoggingLocation());
        Assert.assertEquals("FILE:/var/log/kadmind.log", krbConfig.getAdminLoggingLocation());

        Assert.assertEquals(88, krbConfig.getKdcUdpPort());
        Assert.assertEquals(8014, krbConfig.getKdcTcpPort());
        Assert.assertTrue(krbConfig.isRestrictAnonymousToTgt());
        Assert.assertEquals(4096, krbConfig.getKdcMaxDgramReplySize());

        /* will be moved to LdapLdentityBackend module
        String[] ldapContainerDn = krbConfig.getLdapKerberosContainerDn();
        Assert.assertEquals(3, ldapContainerDn.length);
        Assert.assertEquals("cn=krbcontainer", ldapContainerDn[0]);
        Assert.assertEquals("dc=mit", ldapContainerDn[1]);
        Assert.assertEquals("dc=edu", ldapContainerDn[2]);
        */
    }
}
