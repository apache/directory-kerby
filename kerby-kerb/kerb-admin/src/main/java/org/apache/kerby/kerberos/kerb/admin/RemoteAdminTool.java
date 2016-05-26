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
package org.apache.kerby.kerberos.kerb.admin;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminConfig;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteAddPrincipalCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteDeletePrincipalCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteRenamePrincipalCommand;
import org.apache.kerby.util.OSUtil;

import java.io.File;
import java.util.Scanner;

/**
 * Command use of remote admin
 */
public class RemoteAdminTool {
    private static final String USAGE = (OSUtil.isWindows()
        ? "Usage: bin\\remoteAdmin.cmd" : "Usage: sh bin/remoteAdmin.sh")
        + " <conf-file>\n"
        + "\tExample:\n"
        + "\t\t"
        + (OSUtil.isWindows()
        ? "bin\\remoteAdmin.cmd" : "sh bin/remoteAdmin.sh")
        + " conf\n";

    private static final String LEGAL_COMMANDS = "Available commands are: "
        + "\n"
        + "add_principal, addprinc\n"
        + "                         Add principal\n"
        + "delete_principal, delprinc\n"
        + "                         Delete principal\n"
        + "rename_principal, renprinc\n"
        + "                         Rename principal\n";

    public static void main(String[] args) throws Exception {
        AdminClient adminClient;

        if (args.length != 1) {
            System.err.println(USAGE);
            System.exit(1);
        }

        String confDirPath = args[0];

        File confFile = new File(confDirPath, "adminClient.conf");

        AdminConfig adminConfig = new AdminConfig();
        adminConfig.addKrb5Config(confFile);

        adminClient = new AdminClient(adminConfig);

        String adminRealm = adminConfig.getAdminRealm();

        adminClient.setAdminRealm(adminRealm);
        adminClient.setAllowTcp(true);
        adminClient.setAllowUdp(false);
        adminClient.setAdminTcpPort(adminConfig.getAdminPort());

        adminClient.init();
        System.out.println("admin init successful");

        System.out.println("enter \"command\" to see legal commands.");

        try (Scanner scanner = new Scanner(System.in, "UTF-8")) {
            String input = scanner.nextLine();

            while (!(input.equals("quit") || input.equals("exit") || input.equals("q"))) {
                excute(adminClient, input);
                input = scanner.nextLine();
            }
        }

    }

    private static void excute(AdminClient adminClient, String input) throws KrbException {
        input = input.trim();
        if (input.startsWith("command")) {
            System.out.println(LEGAL_COMMANDS);
            return;
        }

        RemoteCommand executor = null;

        if (input.startsWith("add_principal")
            || input.startsWith("addprinc")) {
            executor = new RemoteAddPrincipalCommand(adminClient);
        } else if (input.startsWith("delete_principal")
            || input.startsWith("delprinc")) {
            executor = new RemoteDeletePrincipalCommand(adminClient);
        } else if (input.startsWith("rename_principal")
            || input.startsWith("renprinc")) {
            executor = new RemoteRenamePrincipalCommand(adminClient);
        } else {
            System.out.println(LEGAL_COMMANDS);
            return;
        }
        executor.execute(input);
    }


}
