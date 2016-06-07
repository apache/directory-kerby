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

import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.junit.Test;

import java.io.File;
import java.net.URL;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for loading configurations form krb5.conf.
 * krb5.conf is the configuration file in MIT Kerberos.
 */
public class KrbConfigLoadTest {

    @Test
    public void test() throws Exception {
        URL confFileUrl = KrbConfigLoadTest.class.getResource("/krb5.conf");
        File confFile = new File(confFileUrl.toURI());

        KrbConfig krbConfig = new KrbConfig();
        krbConfig.addKrb5Config(confFile);
        assertThat(krbConfig.getDefaultRealm()).isEqualTo("KRB.COM");
        assertThat(krbConfig.getKdcRealm()).isEqualTo("TEST.COM");
        assertThat(krbConfig.getKdcHost()).isEqualTo("kdc-server.example.com");
        assertThat(krbConfig.getDnsLookUpKdc()).isFalse();
        assertThat(krbConfig.getDnsLookUpRealm()).isFalse();
        assertThat(krbConfig.getAllowWeakCrypto()).isTrue();
        assertThat(krbConfig.getTicketLifetime()).isEqualTo(24 * 3600);
        assertThat(krbConfig.getRenewLifetime()).isEqualTo(7 * 24 * 3600);
        assertThat(krbConfig.isForwardableAllowed()).isTrue();
        assertThat(krbConfig.getEncryptionTypes()).hasSize(2)
                .contains(EncryptionType.DES_CBC_CRC,
                        EncryptionType.AES128_CTS_HMAC_SHA1_96);
        assertThat(krbConfig.getAllowableClockSkew()).isEqualTo(300);
        assertThat(krbConfig.isProxiableAllowed()).isTrue();
        assertThat(krbConfig.getDefaultTgsEnctypes()).hasSize(1)
                .contains(EncryptionType.DES_CBC_CRC);
        assertThat(krbConfig.getDefaultTktEnctypes()).hasSize(1)
                .contains(EncryptionType.DES_CBC_CRC);
        assertThat(krbConfig.getPkinitAnchors()).hasSize(1);
        assertThat(krbConfig.getPkinitIdentities()).hasSize(2);
        assertThat(krbConfig.getPkinitKdcHostName()).isEqualTo("kdc-server.example.com");
        assertThat(krbConfig.getRealmSection("ATHENA.MIT.EDU")).hasSize(3);
        assertThat(krbConfig.getRealmSectionItems("ATHENA.MIT.EDU", "admin_server")).hasSize(1);
    }
}
