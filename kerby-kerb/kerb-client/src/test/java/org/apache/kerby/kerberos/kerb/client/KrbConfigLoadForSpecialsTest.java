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

import org.junit.Test;

import java.io.File;
import java.net.URL;

import static org.assertj.core.api.Assertions.*;

/**
 * Test for loading configurations form krb5.conf with default kdc realm.
 * krb5.conf is the configuration file in MIT Kerberos.
 */
public class KrbConfigLoadForSpecialsTest {

    @Test
    public void test() throws Exception {
        URL confFileUrl = KrbConfigLoadForSpecialsTest.class.getResource(
                        "/krb5-specials.conf");
        File confFile = new File(confFileUrl.toURI());

        KrbConfig krbConfig = new KrbConfig();
        krbConfig.addKrb5Config(confFile);
        assertThat(krbConfig.getKdcRealm()).isEqualTo("KRB.COM");
        assertThat(krbConfig.getKdcPort()).isEqualTo(88);

        assertThat(krbConfig.allowUdp()).isEqualTo(true);
        assertThat(krbConfig.allowTcp()).isEqualTo(true);
        assertThat(krbConfig.getKdcTcpPort()).isEqualTo(88);
        assertThat(krbConfig.getKdcUdpPort()).isEqualTo(88);
    }
}
