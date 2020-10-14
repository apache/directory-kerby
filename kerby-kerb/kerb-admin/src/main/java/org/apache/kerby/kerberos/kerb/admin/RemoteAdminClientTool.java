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
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteAddPrincipalCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteDeletePrincipalCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteRenamePrincipalCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteListPrincsCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteKeytabAddCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteChangePasswordCommand;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.RemoteGetPrincipalCommand;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcUtil;
import org.apache.kerby.util.OSUtil;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.Completer;
import org.jline.reader.UserInterruptException;
import org.jline.reader.EndOfFileException;
import org.jline.reader.impl.completer.StringsCompleter;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.io.IOException;

/**
 * Command use of remote admin
 */
public class RemoteAdminClientTool {
    private static final Logger LOG = LoggerFactory.getLogger(RemoteAdminClientTool.class);
    private static final String PROMPT = RemoteAdminClientTool.class.getSimpleName() + ".remote";
    private static final String USAGE = (OSUtil.isWindows()
        ? "Usage: bin\\remote-admin-client.cmd" : "Usage: sh bin/remote-admin-client.sh")
        + " <conf-file>\n"
        + "\tExample:\n"
        + "\t\t"
        + (OSUtil.isWindows()
        ? "bin\\remote-admin-client.cmd" : "sh bin/remote-admin-client.sh")
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
        + "ktadd, xst\n"
        + "                         Add entry(s) to a keytab\n"
        + "change_password, cpw\n"
        + "                         Change password\n"
        + "get_principal, getprinc\n"
        + "                         Get principal\n";

    public static void main(String[] args) throws Exception {
        AdminClient adminClient;

        if (args.length < 1) {
            System.err.println(USAGE);
            System.exit(1);
        }

        String confDirPath = args[0];

        File confFile = new File(confDirPath, "adminClient.conf");

        final AdminConfig adminConfig = new AdminConfig();
        adminConfig.addKrb5Config(confFile);

        KdcConfig tmpKdcConfig = KdcUtil.getKdcConfig(new File(confDirPath));
        if (tmpKdcConfig == null) {
            tmpKdcConfig = new KdcConfig();
        }

        try {
            Krb5Conf krb5Conf = new Krb5Conf(new File(confDirPath), tmpKdcConfig);
            krb5Conf.initKrb5conf();
        } catch (IOException e) {
            throw new KrbException("Failed to make krb5.conf", e);
        }

        adminClient = new AdminClient(adminConfig);

        File keytabFile = new File(adminConfig.getKeyTabFile());
        if (!keytabFile.exists()) {
            System.err.println("Need the valid keytab file value in conf file.");
            return;
        }

        String adminRealm = adminConfig.getAdminRealm();

        adminClient.setAdminRealm(adminRealm);
        adminClient.setAllowTcp(true);
        adminClient.setAllowUdp(false);
        adminClient.setAdminTcpPort(adminConfig.getAdminPort());

        adminClient.init();
        System.out.println("admin init successful");

        String adminPrincipal = KrbUtil.makeKadminPrincipal(
            adminClient.getSetting().getKdcRealm()).getName();
        Subject subject = null;
        try {
            subject = AuthUtil.loginUsingKeytab(adminPrincipal,
                new File(adminConfig.getKeyTabFile()));
        } catch (LoginException e) {
            LOG.error("Fail to login using keytab. " + e);
            return;
        }

        // set login subject, used by SASL negotiation
        adminClient.setSubject(subject);

        System.out.println("enter \"command\" to see legal commands.");

        Completer completer = new StringsCompleter("add_principal", "delete_principal", "rename_principal",
                "list_principals", "ktadd", "change_password", "get_principal");

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
                execute(adminClient, line);
            } catch (UserInterruptException | EndOfFileException ex) {
                break;
            } catch (KrbException e) {
                System.err.println(e.getMessage());
            }
        }
    }

    private static void execute(AdminClient adminClient, String input) throws KrbException {
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
        } else if (input.startsWith("list_principals")
            || input.startsWith("listprincs")) {
            executor = new RemoteListPrincsCommand(adminClient);
        } else if (input.startsWith("ktadd")
            || input.startsWith("xst")) {
            executor = new RemoteKeytabAddCommand(adminClient);
        } else if (input.startsWith("change_password")
                || input.startsWith("cpw")) {
            executor = new RemoteChangePasswordCommand(adminClient);
        } else if (input.startsWith("get_principal")
                || input.startsWith("getprinc")) {
            executor = new RemoteGetPrincipalCommand(adminClient);
        } else {
            System.out.println(LEGAL_COMMANDS);
            return;
        }
        executor.execute(input);
    }
}
