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
import org.apache.kerby.util.OSUtil;

import java.io.Console;
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

    private static final String COMMAND = "Usage: add_principal [options] <principal-name>\n"
        + "delete_principal <principal_name>\n"
        + "\tExample:\n"
        + "\t\tadd_principal -pw mypassword alice\n"
        + "\t\tdelete_principal alice\n";

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
            System.out.println(COMMAND);
            return;
        }

        String[] temp = input.split("\\s+");

        if (temp[0].startsWith("add_principal")) {
            String adminRealm = adminClient.getAdminConfig().getAdminRealm();
            String clientPrincipal = temp[temp.length - 1] + "@" + adminRealm;
            if (!temp[1].startsWith("-")) {
                adminClient.requestAddPrincipal(clientPrincipal);
            } else if (temp[1].startsWith("-nokey")) {
                adminClient.requestAddPrincipal(clientPrincipal);
            } else if (temp[1].startsWith("-pw")) {
                String password = temp[2];
                adminClient.requestAddPrincipal(clientPrincipal, password);
            } else {
                System.out.println("add_principal command format error.\n"
                + "Please input command for further reference.");
            }

        } else if (temp[0].startsWith("delete_principal")) {
            String principal = temp[1] + "@"
                + adminClient.getAdminConfig().getAdminRealm();
            String reply;
            Console console = System.console();
            String prompt = "Are you sure to delete the principal? (yes/no, YES/NO, y/n, Y/N) ";
            if (console == null) {
                System.out.println("Couldn't get Console instance, "
                    + "maybe you're running this from within an IDE. "
                    + "Use scanner to read password.");
                Scanner scanner = new Scanner(System.in, "UTF-8");
                reply = getReply(scanner, prompt);
            } else {
                reply = getReply(console, prompt);
            }
            if (reply.equals("yes") || reply.equals("YES") || reply.equals("y") || reply.equals("Y")) {
                adminClient.requestDeletePrincipal(principal);
            } else if (reply.equals("no") || reply.equals("NO") || reply.equals("n") || reply.equals("N")) {
                System.out.println("Principal \"" + principal + "\"  not deleted.");
            } else {
                System.err.println("Unknown request, fail to delete the principal.");
            }
        } else {
            System.out.println("remain to be developed...");
        }
    }

    private static String getReply(Scanner scanner, String prompt) {
        System.out.println(prompt);
        return scanner.nextLine().trim();
    }

    private static String getReply(Console console, String prompt) {
        console.printf(prompt);
        String line = console.readLine();
        return line;
    }
}
