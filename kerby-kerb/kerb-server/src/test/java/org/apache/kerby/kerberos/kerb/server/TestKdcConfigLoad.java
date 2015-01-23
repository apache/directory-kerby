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

        Assert.assertEquals(krbConfig.getDefaultLoggingLocation(), "FILE:/var/log/krb5libs.log");
        Assert.assertEquals(krbConfig.getKdcLoggingLocation(), "FILE:/var/log/krb5kdc.log");
        Assert.assertEquals(krbConfig.getAdminLoggingLocation(), "FILE:/var/log/kadmind.log");

        Assert.assertEquals(krbConfig.getKdcUdpPort(), 88);
        Assert.assertEquals(krbConfig.getKdcTcpPort(), 8014);
        Assert.assertTrue(krbConfig.isRestrictAnonymousToTgt());
        Assert.assertEquals(krbConfig.getKdcMaxDgramReplySize(), 4096);

        String[] ldapContainerDn = krbConfig.getLdapKerberosContainerDn();
        Assert.assertEquals(ldapContainerDn.length, 3);
        Assert.assertEquals(ldapContainerDn[0], "cn=krbcontainer");
        Assert.assertEquals(ldapContainerDn[1], "dc=mit");
        Assert.assertEquals(ldapContainerDn[2], "dc=edu");
    }
}
