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
package org.apache.kerby.kerberos.tool.admin.remote;

import org.apache.kerby.has.client.HasAuthAdminClient;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.util.HasUtil;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.tool.admin.remote.cmd.AddPrincipalRemoteCmd;
import org.apache.kerby.kerberos.tool.admin.remote.cmd.AddPrincipalsRemoteCmd;
import org.apache.kerby.kerberos.tool.admin.remote.cmd.AdminRemoteCmd;
import org.apache.kerby.kerberos.tool.admin.remote.cmd.ChangePasswordRemoteCmd;
import org.apache.kerby.kerberos.tool.admin.remote.cmd.DeletePrincipalRemoteCmd;
import org.apache.kerby.kerberos.tool.admin.remote.cmd.DisableConfRemoteCmd;
import org.apache.kerby.kerberos.tool.admin.remote.cmd.EnableConfRemoteCmd;
import org.apache.kerby.kerberos.tool.admin.remote.cmd.ExportKeytabsRemoteCmd;
import org.apache.kerby.kerberos.tool.admin.remote.cmd.GetHostRolesRemoteCmd;
import org.apache.kerby.kerberos.tool.admin.remote.cmd.ListPrincipalsRemoteCmd;
import org.apache.kerby.kerberos.tool.admin.remote.cmd.RenamePrincipalRemoteCmd;
import org.apache.kerby.util.OSUtil;
import org.jline.reader.Completer;
import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.UserInterruptException;
import org.jline.reader.impl.completer.StringsCompleter;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;

import java.io.File;
import java.io.IOException;

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
        + "change_password, cpw\n"
        + "                         Change password\n"
        + "list_principals, listprincs\n"
        + "                         List principals\n"
        + "get_hostroles, hostroles\n"
        + "                         Get hostRoles\n"
        + "export_keytabs, expkeytabs\n"
        + "                         Export keytabs\n"
        + "add_principals, addprincs\n"
        + "                         Add principals\n"
        + "enable_configure, enable\n"
        + "                         Enable configure\n"
        + "disable_configure, disable\n"
        + "                         Disable configure\n";

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

        Completer completer = new StringsCompleter("add_principal",
                "delete_principal", "rename_principal", "change_password", "list_principals",
                "get_hostroles", "export_keytabs", "add_principals", "enable_configure",
                "disable_configure");

        Terminal terminal = null;
        try {
            terminal = TerminalBuilder.terminal();
        } catch (IOException e) {
            e.printStackTrace();
        }
        LineReader lineReader = LineReaderBuilder.builder().completer(completer).terminal(terminal).build();

        while (true) {
            try {
                String line = lineReader.readLine(PROMPT + ": ");
                if ("quit".equals(line) || "exit".equals(line) || "q".equals(line)) {
                    break;
                }
                execute(authHasAdminClient, line);
            } catch (UserInterruptException | EndOfFileException ex) {
                break;
            } catch (KrbException e) {
                System.err.println(e.getMessage());
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
        } else if (cmd.equals("change_password")
            || cmd.startsWith("cpw")) {
            executor = new ChangePasswordRemoteCmd(hasAuthAdminClient);
        } else if (cmd.equals("list_principals")
            || cmd.equals("listprincs")) {
            executor = new ListPrincipalsRemoteCmd(hasAuthAdminClient);
        } else if (cmd.equals("get_hostroles")
            || cmd.equals("hostroles")) {
            executor = new GetHostRolesRemoteCmd(hasAuthAdminClient);
        } else if (cmd.equals("add_principals")
            || cmd.equals("addprincs")) {
            executor = new AddPrincipalsRemoteCmd(hasAuthAdminClient);
        } else if (cmd.equals("export_keytabs")
            || cmd.equals("expkeytabs")) {
            executor = new ExportKeytabsRemoteCmd(hasAuthAdminClient);
        } else if (cmd.equals("enable_configure")
            || cmd.equals("enable")) {
            executor = new EnableConfRemoteCmd(hasAuthAdminClient);
        } else if (cmd.equals("disable_configure")
            || cmd.equals("disable")) {
            executor = new DisableConfRemoteCmd(hasAuthAdminClient);
        } else {
            System.out.println(LEGAL_COMMANDS);
            return;
        }
        executor.execute(items);
    }

}
