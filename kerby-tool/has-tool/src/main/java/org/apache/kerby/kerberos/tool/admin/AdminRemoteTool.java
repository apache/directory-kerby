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
package org.apache.kerby.kerberos.tool.admin;

import org.apache.kerby.has.client.HasAuthAdminClient;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.util.HasUtil;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.tool.admin.cmd.AddPrincipalRemoteCmd;
import org.apache.kerby.kerberos.tool.admin.cmd.AdminRemoteCmd;
import org.apache.kerby.kerberos.tool.admin.cmd.DeletePrincipalRemoteCmd;
import org.apache.kerby.kerberos.tool.admin.cmd.ListPrincipalsRemoteCmd;
import org.apache.kerby.kerberos.tool.admin.cmd.RenamePrincipalRemoteCmd;
import org.apache.kerby.util.OSUtil;

import java.io.File;
import java.util.Scanner;

public class AdminRemoteTool {

    private static final String PROMPT = "admin.remote";
    private static final String USAGE = (OSUtil.isWindows()
        ? "Usage: bin\\admin-remote.cmd" : "Usage: sh bin/admin-remote.sh")
        + " <conf-file>\n"
        + "\tExample:\n"
        + "\t\t"
        + (OSUtil.isWindows()
        ? "bin\\admin-remote.cmd" : "sh bin/admin-remote.sh")
        + " conf\n";

    private static final String LEGAL_COMMANDS = "Available commands are: "
        + "\n"
        + "add_principal, addprinc\n"
        + "                         Add principal\n"
        + "delete_principal, delprinc\n"
        + "                         Delete principal\n"
        + "rename_principal, renprinc\n"
        + "                         Rename principal\n"
        + "list_principals, listprincs\n"
        + "                         List principals\n";

    public static void main(String[] args) {

        HasAuthAdminClient authHasAdminClient = null;

        if (args.length < 1) {
            System.err.println(USAGE);
            System.exit(1);
        }

        String confDirPath = args[0];
        File confFile = new File(confDirPath, "admin.conf");
        HasConfig hasConfig;
        try {
            hasConfig = HasUtil.getHasConfig(confFile);
        } catch (HasException e) {
            System.err.println(e.getMessage());
            return;
        }

        if (hasConfig.getFilterAuthType().equals("kerberos")) {
            authHasAdminClient = new HasAuthAdminClient(hasConfig);
        }

        System.out.println("enter \"cmd\" to see legal commands.");
        System.out.print(PROMPT + ": ");

        try (Scanner scanner = new Scanner(System.in, "UTF-8")) {
            String input = scanner.nextLine();

            while (!(input.equals("quit") || input.equals("exit") || input.equals("q"))) {
                try {
                    execute(authHasAdminClient, input);
                } catch (KrbException e) {
                    System.err.println(e.getMessage());
                }
                System.out.print(PROMPT + ": ");
                input = scanner.nextLine();
            }
        }
    }

    private static void execute(HasAuthAdminClient hasAuthAdminClient,
                               String input) throws KrbException {
        input = input.trim();
        if (input.startsWith("cmd")) {
            System.out.println(LEGAL_COMMANDS);
            return;
        }
        AdminRemoteCmd executor;

        String[] items = input.split("\\s+");
        String cmd = items[0];

        if (cmd.equals("add_principal")
            || cmd.equals("addprinc")) {
            executor = new AddPrincipalRemoteCmd(hasAuthAdminClient);
        } else if (cmd.equals("delete_principal")
            || cmd.equals("delprinc")) {
            executor = new DeletePrincipalRemoteCmd(hasAuthAdminClient);
        } else if (cmd.equals("rename_principal")
            || cmd.equals("renprinc")) {
            executor = new RenamePrincipalRemoteCmd(hasAuthAdminClient);
        } else if (cmd.equals("list_principals")
            || cmd.equals("listprincs")) {
            executor = new ListPrincipalsRemoteCmd(hasAuthAdminClient);
        } else {
            System.out.println(LEGAL_COMMANDS);
            return;
        }
        executor.execute(items);
    }

}
