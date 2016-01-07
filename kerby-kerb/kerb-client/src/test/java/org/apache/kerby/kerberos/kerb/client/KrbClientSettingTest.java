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

public class KrbClientSettingTest {

    @Test
    public void testKdcServerMannualSetting() throws Exception {
        URL confFileUrl = KrbConfigLoadForSpecialsTest.class.getResource(
            "/krb5-specials.conf");
        File confFile = new File(confFileUrl.toURI());

        KrbConfig conf = new KrbConfig();
        conf.addKrb5Config(confFile);
        KrbClient krbClient = new KrbClient(conf);

        KrbSetting krbSetting = krbClient.getSetting();

        assertThat(krbSetting.getKdcRealm()).isEqualTo("KRB.COM");

        assertThat(krbSetting.allowUdp()).isEqualTo(true);
        assertThat(krbSetting.allowTcp()).isEqualTo(true);
        assertThat(krbSetting.getKdcTcpPort()).isEqualTo(88);
        assertThat(krbSetting.getKdcUdpPort()).isEqualTo(88);
        
        krbClient.setKdcHost("localhost");
        krbClient.setKdcRealm("TEST2.COM");
        krbClient.setKdcTcpPort(12345);


        assertThat(krbSetting.getKdcHost()).isEqualTo("localhost");
        assertThat(krbSetting.getKdcTcpPort()).isEqualTo(12345);
        assertThat(krbSetting.getKdcRealm()).isEqualTo("TEST2.COM");
    }

}