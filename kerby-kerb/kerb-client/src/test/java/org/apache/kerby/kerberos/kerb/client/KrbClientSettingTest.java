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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class KrbClientSettingTest {

    @Test
    public void testKdcServerMannualSetting() throws KrbException {
        KrbClient krbClient = new KrbClient(new KrbConfig());

        krbClient.setKdcHost("localhost");
        krbClient.setKdcRealm("TEST2.COM");
        krbClient.setKdcTcpPort(12345);

        KrbSetting krbSetting = krbClient.getSetting();
        assertThat(krbSetting.getKdcHost()).isEqualTo("localhost");
        assertThat(krbSetting.allowTcp()).isEqualTo(true);
        assertThat(krbSetting.getKdcTcpPort()).isEqualTo(12345);
        assertThat(krbSetting.allowUdp()).isEqualTo(false);
        assertThat(krbSetting.getKdcUdpPort()).isEqualTo(-1);
        assertThat(krbSetting.getKdcRealm()).isEqualTo("TEST2.COM");
    }

}