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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class KdcSettingTest {

    @Test
    public void testKdcServerMannualSetting() throws KrbException {
        KdcServer kerbServer = new KdcServer();
        kerbServer.setKdcHost("localhost");
        kerbServer.setKdcRealm("TEST2.COM");
        kerbServer.setKdcTcpPort(12345);

        kerbServer.init();

        KdcSetting kdcSetting = kerbServer.getKdcSetting();
        assertThat(kdcSetting.getKdcHost()).isEqualTo("localhost");
        assertThat(kdcSetting.getKdcTcpPort()).isEqualTo(12345);
        assertThat(kdcSetting.getKdcRealm()).isEqualTo("TEST2.COM");
    }

}