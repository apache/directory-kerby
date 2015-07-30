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

        KdcConfig kdcConfig = new KdcConfig();
        kdcConfig.addIniConfig(confFile);

        assertThat(kdcConfig.getKdcHost()).isEqualTo("localhost");
        assertThat(kdcConfig.getKdcUdpPort()).isEqualTo(88);
        assertThat(kdcConfig.getKdcTcpPort()).isEqualTo(8014);
        assertThat(kdcConfig.getKdcRealm()).isEqualTo("TEST.COM");
        assertThat(kdcConfig.isRestrictAnonymousToTgt()).isTrue();
        assertThat(kdcConfig.getKdcMaxDgramReplySize()).isEqualTo(4096);
    }

    @Test
    public void testManualConfiguration() {
        KdcConfig kdcConfig = new KdcConfig();

        kdcConfig.setString(KdcConfigKey.KDC_HOST, "localhost");
        kdcConfig.setInt(KdcConfigKey.KDC_TCP_PORT, 12345);
        kdcConfig.setString(KdcConfigKey.KDC_REALM, "TEST2.COM");

        assertThat(kdcConfig.getKdcHost()).isEqualTo("localhost");
        assertThat(kdcConfig.getKdcTcpPort()).isEqualTo(12345);
        assertThat(kdcConfig.getKdcRealm()).isEqualTo("TEST2.COM");
    }

    @Test
    public void testConfigurationDefaults() {
        KdcConfig kdcConfig = new KdcConfig();

        assertThat(kdcConfig.getKdcHost()).isEqualTo(
                KdcConfigKey.KDC_HOST.getDefaultValue());
        assertThat(kdcConfig.getKdcTcpPort()).isEqualTo(-1);
        assertThat(kdcConfig.getKdcRealm()).isEqualTo(
                KdcConfigKey.KDC_REALM.getDefaultValue()
        );
    }
}
