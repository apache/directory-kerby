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
package org.apache.hadoop.has.tool.client.hadmin.remote;

import org.apache.hadoop.has.client.HasAdminClient;
import org.apache.hadoop.has.client.HasAuthAdminClient;
import org.apache.hadoop.has.common.HasConfig;
import org.apache.hadoop.has.common.HasException;
import org.apache.hadoop.has.common.util.HasUtil;
import org.apache.hadoop.has.tool.client.hadmin.remote.cmd.HadminRemoteCmd;
import org.apache.hadoop.has.tool.client.hadmin.remote.cmd.HasRemoteAddPrincipalCmd;
import org.apache.hadoop.has.tool.client.hadmin.remote.cmd.HasRemoteCreatePrincipalsCmd;
import org.apache.hadoop.has.tool.client.hadmin.remote.cmd.HasRemoteDeletePrincipalCmd;
import org.apache.hadoop.has.tool.client.hadmin.remote.cmd.HasRemoteDisableConfCmd;
import org.apache.hadoop.has.tool.client.hadmin.remote.cmd.HasRemoteEnableConfCmd;
import org.apache.hadoop.has.tool.client.hadmin.remote.cmd.HasRemoteExportKeytabsCmd;
import org.apache.hadoop.has.tool.client.hadmin.remote.cmd.HasRemoteGetHostRolesCmd;
import org.apache.hadoop.has.tool.client.hadmin.remote.cmd.HasRemoteGetPrincipalsCmd;
import org.apache.hadoop.has.tool.client.hadmin.remote.cmd.HasRemoteRenamePrincipalCmd;
import org.apache.kerby.util.OSUtil;

import java.io.File;
import java.util.Scanner;

public class HadminRemoteTool {

    private static final String PROMPT = HadminRemoteTool.class.getSimpleName() + ".remote";
    private static final String USAGE = (OSUtil.isWindows()
        ? "Usage: bin\\hadmin-remote.cmd" : "Usage: sh bin/hadmin-remote.sh")
        + " <conf-file>\n"
        + "\tExample:\n"
        + "\t\t"
        + (OSUtil.isWindows()
        ? "bin\\hadmin-remote.cmd" : "sh bin/hadmin-remote.sh")
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
        + "                         List principals\n"
        + "get_hostroles, hostroles\n"
        + "                         Get hostRoles\n"
        + "export_keytabs, expkeytabs\n"
        + "                         Export keytabs\n"
        + "create_principals, creprincs\n"
        + "                         Create principals\n"
        + "enable_configure, enable\n"
        + "                         Enable configure\n"
        + "disable_configure, disable\n"
        + "                         Disable configure\n";

    public static void main(String[] args) {
        HasAdminClient hadmin;
        HasAuthAdminClient authHasAdminClient = null;

        if (args.length < 1) {
            System.err.println(USAGE);
            System.exit(1);
        }

        String confDirPath = args[0];
        File confFile = new File(confDirPath, "hadmin.conf");
        HasConfig hasConfig;
        try {
            hasConfig = HasUtil.getHasConfig(confFile);
        } catch (HasException e) {
            System.err.println(e.getMessage());
            return;
        }

        hadmin = new HasAdminClient(hasConfig);

        if (hasConfig.getFilterAuthType().equals("kerberos")) {
            authHasAdminClient = new HasAuthAdminClient(hasConfig);
        }

        System.out.println("enter \"cmd\" to see legal commands.");
        System.out.print(PROMPT + ": ");

        try (Scanner scanner = new Scanner(System.in, "UTF-8")) {
            String input = scanner.nextLine();

            while (!(input.equals("quit") || input.equals("exit") || input.equals("q"))) {
                try {
                    execute(hadmin, authHasAdminClient, input);
                } catch (HasException e) {
                    System.err.println(e.getMessage());
                }
                System.out.print(PROMPT + ": ");
                input = scanner.nextLine();
            }
        }
    }

    private static void execute(HasAdminClient hadmin, HasAuthAdminClient hasAuthAdminClient,
                               String input) throws HasException {
        input = input.trim();
        if (input.startsWith("cmd")) {
            System.out.println(LEGAL_COMMANDS);
            return;
        }
        HadminRemoteCmd executor;

        String[] items = input.split("\\s+");
        String cmd = items[0];

        if (cmd.equals("add_principal")
            || cmd.equals("addprinc")) {
            executor = new HasRemoteAddPrincipalCmd(hadmin, hasAuthAdminClient);
        } else if (cmd.equals("delete_principal")
            || cmd.equals("delprinc")) {
            executor = new HasRemoteDeletePrincipalCmd(hadmin, hasAuthAdminClient);
        } else if (cmd.equals("rename_principal")
            || cmd.equals("renprinc")) {
            executor = new HasRemoteRenamePrincipalCmd(hadmin, hasAuthAdminClient);
        } else if (cmd.equals("list_principals")
            || cmd.equals("listprincs")) {
            executor = new HasRemoteGetPrincipalsCmd(hadmin, hasAuthAdminClient);
        } else if (cmd.equals("get_hostroles")
            || cmd.equals("hostroles")) {
            executor = new HasRemoteGetHostRolesCmd(hadmin, hasAuthAdminClient);
        } else if (cmd.equals("create_principals")
            || cmd.equals("creprincs")) {
            executor = new HasRemoteCreatePrincipalsCmd(hadmin, hasAuthAdminClient);
        } else if (cmd.equals("export_keytabs")
            || cmd.equals("expkeytabs")) {
            executor = new HasRemoteExportKeytabsCmd(hadmin, hasAuthAdminClient);
        } else if (cmd.equals("enable_configure")
            || cmd.equals("enable")) {
            executor = new HasRemoteEnableConfCmd(hadmin, hasAuthAdminClient);
        } else if (cmd.equals("disable_configure")
            || cmd.equals("disable")) {
            executor = new HasRemoteDisableConfCmd(hadmin, hasAuthAdminClient);
        } else {
            System.out.println(LEGAL_COMMANDS);
            return;
        }
        executor.execute(items);
    }

}
