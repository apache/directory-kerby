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
package org.apache.kerby.kerberos.kerb.client;

import org.apache.kerby.config.Conf;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

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

        Assert.assertEquals("KRB.COM", krbConfig.getDefaultRealm());
        Assert.assertFalse(krbConfig.getDnsLookUpKdc());
        Assert.assertFalse(krbConfig.getDnsLookUpRealm());
        Assert.assertTrue(krbConfig.getAllowWeakCrypto());
        Assert.assertEquals(24 * 3600, krbConfig.getTicketLifetime());
        Assert.assertEquals(7 * 24 * 3600, krbConfig.getRenewLifetime());
        Assert.assertTrue(krbConfig.isForwardableAllowed());
        Assert.assertEquals(2, krbConfig.getEncryptionTypes().size());
        Assert.assertEquals(EncryptionType.DES_CBC_CRC, krbConfig.getEncryptionTypes().get(0));
        Assert.assertEquals(EncryptionType.AES128_CTS_HMAC_SHA1_96, krbConfig.getEncryptionTypes().get(1));
        Assert.assertEquals(300, krbConfig.getAllowableClockSkew());
        Assert.assertTrue(krbConfig.isProxiableAllowed());
        Assert.assertEquals(1, krbConfig.getDefaultTgsEnctypes().size());
        Assert.assertEquals(EncryptionType.DES_CBC_CRC, krbConfig.getDefaultTgsEnctypes().get(0));
        Assert.assertEquals(1, krbConfig.getDefaultTktEnctypes().size());
        Assert.assertEquals(EncryptionType.DES_CBC_CRC, krbConfig.getDefaultTktEnctypes().get(0));

        Assert.assertEquals("FILE:/var/log/krb5libs.log", krbConfig.getDefaultLoggingLocation());
        Assert.assertEquals("FILE:/var/log/krb5kdc.log", krbConfig.getKdcLoggingLocation());
        Assert.assertEquals("FILE:/var/log/kadmind.log", krbConfig.getAdminLoggingLocation());

    }
}
