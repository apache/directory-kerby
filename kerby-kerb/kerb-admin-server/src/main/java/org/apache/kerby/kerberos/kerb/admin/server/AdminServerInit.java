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
package org.apache.kerby.kerberos.kerb.admin.server;


import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServer;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.util.OSUtil;

import java.io.File;

public class AdminServerInit {
    private static final String USAGE = (OSUtil.isWindows()
        ? "Usage: bin\\adminServer.cmd" : "Usage: sh bin/adminServer.sh")
        + " <conf-file>\n"
        + "\tExample:\n"
        + "\t\t"
        + (OSUtil.isWindows()
        ? "bin\\kadmin.cmd" : "sh bin/kadmin.sh")
        + " conf\\adminServer.conf\n";

    public static void main(String[] args) throws Exception {

        if (args.length != 1) {
            System.err.println(USAGE);
            System.exit(1);
        }

        String confDirPath = args[0];
        File serverConfFile = new File(confDirPath);

        if (!serverConfFile.exists()) {
            System.err.println("Invalid or not exist conf");
            System.exit(2);
        }

        /**
         * Below two lines cannot be used in jar.
         * Because url is not hierarchical
         */
        //URL serverConfFileUrl = AdminServerInit.class.getResource("/adminServer.conf");
        //File serverConfFile = new File(serverConfFileUrl.toURI());
        AdminServerConfig adminServerConfig = new AdminServerConfig();
        adminServerConfig.addKrb5Config(serverConfFile);

        BackendConfig backendConfig = new BackendConfig();

        AdminServer adminServer = new AdminServer(adminServerConfig, backendConfig);
        adminServer.setAdminHost(adminServerConfig.getAdminHost());
        adminServer.setAllowTcp(true);
        adminServer.setAllowUdp(false);
        adminServer.setAdminServerPort(adminServerConfig.getAdminPort());

        try {
            adminServer.init();
        } catch (KrbException e) {
            System.err.println("Errors occurred when start admin server:  " + e.getMessage());
            System.exit(3);
        }
        adminServer.start();
        System.out.println("Admin server started!");
    }
}
