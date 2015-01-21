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
package org.apache.kerberos.kerb.client;

import org.apache.haox.config.Conf;
import org.apache.kerberos.kerb.spec.common.EncryptionType;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

import org.junit.Test;
import org.junit.Assert;


/**
 * Test for loading configurations form krb5.conf.
 * krb5.conf is the configuration file in MIT Kerberos.
 */
public class TestKrbConfigLoad {

    @Test
    public void test() throws IOException, URISyntaxException {
        URL confFileUrl = TestKrbConfigLoad.class.getResource("/krb5.conf");
        File confFile = new File(confFileUrl.toURI());

        KrbConfig krbConfig = new KrbConfig();
        Conf conf = krbConfig.getConf();
        conf.addIniConfig(confFile);

        Assert.assertEquals(krbConfig.getDefaultRealm(), "KRB.COM");
        Assert.assertFalse(krbConfig.getDnsLookUpKdc());
        Assert.assertFalse(krbConfig.getDnsLookUpRealm());
        Assert.assertTrue(krbConfig.getAllowWeakCrypto());
        Assert.assertEquals(krbConfig.getTicketLifetime(), 24 * 3600);
        Assert.assertEquals(krbConfig.getRenewLifetime(), 7 * 24 * 3600);
        Assert.assertTrue(krbConfig.isForwardableAllowed());
        Assert.assertEquals(krbConfig.getEncryptionTypes().size(), 2);
        Assert.assertEquals(krbConfig.getEncryptionTypes().get(0), EncryptionType.DES_CBC_CRC);
        Assert.assertEquals(krbConfig.getEncryptionTypes().get(1), EncryptionType.AES128_CTS_HMAC_SHA1_96);
        Assert.assertEquals(krbConfig.getAllowableClockSkew(), 300);
        Assert.assertTrue(krbConfig.isProxiableAllowed());
        Assert.assertEquals(krbConfig.getDefaultTgsEnctypes().size(), 1);
        Assert.assertEquals(krbConfig.getDefaultTgsEnctypes().get(0), EncryptionType.DES_CBC_CRC);
        Assert.assertEquals(krbConfig.getDefaultTktEnctypes().size(), 1);
        Assert.assertEquals(krbConfig.getDefaultTktEnctypes().get(0), EncryptionType.DES_CBC_CRC);

        Assert.assertEquals(krbConfig.getDefaultLoggingLocation(), "FILE:/var/log/krb5libs.log");
        Assert.assertEquals(krbConfig.getKdcLoggingLocation(), "FILE:/var/log/krb5kdc.log");
        Assert.assertEquals(krbConfig.getAdminLoggingLocation(), "FILE:/var/log/kadmind.log");

    }
}
