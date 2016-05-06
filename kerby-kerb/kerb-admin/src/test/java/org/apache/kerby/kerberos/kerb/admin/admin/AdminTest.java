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
/*package org.apache.kerby.kerberos.kerb.admin.admin;

import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminConfig;
import org.junit.Test;

import java.io.File;
import java.net.URL;

public class AdminTest {
    private final String clientPrincipalName = "alice";
    private AdminClient adminClient;

    @Test
    public void testAdminClient() throws Exception {

        URL confFileUrl = AdminTest.class.getResource("/adminClient.conf");
        File confFile = new File(confFileUrl.toURI());

        AdminConfig adminConfig = new AdminConfig();
        adminConfig.addKrb5Config(confFile);

        adminClient = new AdminClient(adminConfig);

        String adminRealm = adminConfig.getAdminRealm();
        String clientPrincipal = clientPrincipalName + "@" + adminRealm;

        adminClient.setAdminRealm(adminRealm);
        adminClient.setAllowTcp(true);
        adminClient.setAllowUdp(false);
        adminClient.setAdminTcpPort(adminConfig.getAdminPort());

        adminClient.init();
        adminClient.requestAddPrincial(clientPrincipal);
    }
}
*/