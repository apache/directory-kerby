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
package org.apache.kerby.kerberos.tool.admin.local;

import org.apache.kerby.KOptions;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.server.admin.LocalHadmin;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.KadminOption;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.tool.admin.local.cmd.KeytabCommand;
import org.apache.kerby.kerberos.tool.admin.local.cmd.AddPrincipalsCommand;
import org.apache.kerby.kerberos.tool.admin.local.cmd.DeployHTTPSCertsCommand;
import org.apache.kerby.kerberos.tool.admin.local.cmd.DisableConfigureCommand;
import org.apache.kerby.kerberos.tool.admin.local.cmd.EnableConfigureCommand;
import org.apache.kerby.kerberos.tool.admin.local.cmd.ExportKeytabsCommand;
import org.apache.kerby.kerberos.tool.admin.local.cmd.GetHostRolesCommand;
import org.apache.kerby.kerberos.tool.admin.local.cmd.HadminCommand;
import org.apache.kerby.kerberos.tool.kadmin.AuthUtil;
import org.apache.kerby.kerberos.tool.kadmin.Krb5Conf;
import org.apache.kerby.kerberos.tool.kadmin.ToolUtil;
import org.apache.kerby.kerberos.tool.kadmin.command.AddPrincipalCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.ChangePasswordCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.DeletePrincipalCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.GetPrincipalCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.KadminCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.KeytabAddCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.ListPrincipalCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.RenamePrincipalCommand;
import org.apache.kerby.util.OSUtil;
import org.jline.reader.Completer;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.impl.completer.StringsCompleter;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.util.Map;
import java.util.Set;

public class AdminLocalTool {
    private static final Logger LOG = LoggerFactory.getLogger(AdminLocalTool.class);
    private static File confDir;

    private static final String PROMPT = "admin.local";
    private static  final String USAGE = (OSUtil.isWindows()
            ? "Usage: bin\\admin-local.cmd" : "Usage: sh bin/admin-local.sh")
            + " <conf-dir> <-c cache_name>|<-k keytab>\n"
            + "\tExample:\n"
            + "\t\t"
            + (OSUtil.isWindows()
            ? "bin\\admin-local.cmd" : "sh bin/admin-local.sh")
            + " conf -k admin.keytab\n";

    private static void printUsage(String error) {
        System.err.println(error + "\n");
        System.err.println(USAGE);
        System.exit(-1);
    }

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
        + "get_principal, getprinc\n"
        + "                         Get principal\n"
        + "list_principals, listprincs\n"
        + "                         List principals\n"
        + "ktadd, xst\n"
        + "                         Add entry(s) to a keytab\n"
        + "get_hostroles, hostroles\n"
        + "                         Get hostRoles\n"
        + "export_keytabs, expkeytabs\n"
        + "                         Export keytabs\n"
        + "create_principals, creprincs\n"
        + "                         Create principals\n"
        + "enable_configure, enable\n"
        + "                         Enable configure\n"
        + "disable_configure, disable\n"
        + "                         Disable configure\n"
        + "keytab\n"
        + "                         Add principals, export keytabs, and deploy keytabs\n"
        + "deploy_https, dephttps\n"
        + "                         Deploy https\n";

    private static void execute(LocalKadmin kadmin, LocalHadmin hadmin, String input) throws HasException {
        // Omit the leading and trailing whitespace.
        input = input.trim();
        if (input.startsWith("cmd")) {
            System.out.println(LEGAL_COMMANDS);
            return;
        }

        String[] items = input.split("\\s+");
        String cmd = items[0];
        HadminCommand hadminExecutor = null;
        KadminCommand kadminExecutor = null;
        if (cmd.startsWith("add_principal")
            || cmd.startsWith("addprinc")) {
            kadminExecutor = new AddPrincipalCommand(kadmin);
        } else if (cmd.startsWith("delete_principal")
            || cmd.startsWith("delprinc")) {
            kadminExecutor = new DeletePrincipalCommand(kadmin);
        } else if (cmd.startsWith("rename_principal")
            || cmd.startsWith("renprinc")) {
            kadminExecutor = new RenamePrincipalCommand(kadmin);
        } else if (cmd.startsWith("change_password")
                || cmd.startsWith("cpw")) {
            kadminExecutor = new ChangePasswordCommand(kadmin);
        } else if (cmd.startsWith("list_principals")
            || cmd.startsWith("listprincs")) {
            kadminExecutor = new ListPrincipalCommand(kadmin);
        } else if (cmd.startsWith("get_principal")
                || cmd.startsWith("getprinc")) {
            kadminExecutor = new GetPrincipalCommand(kadmin);
        } else if (cmd.startsWith("ktadd")
            || cmd.startsWith("xst")) {
            kadminExecutor = new KeytabAddCommand(kadmin);
        } else if (cmd.startsWith("get_hostroles")
            || cmd.startsWith("hostroles")) {
            hadminExecutor = new GetHostRolesCommand(hadmin);
        } else if (cmd.startsWith("create_principals")
            || cmd.startsWith("creprincs")) {
            hadminExecutor = new AddPrincipalsCommand(hadmin);
        } else if (cmd.startsWith("export_keytabs")
            || cmd.startsWith("expkeytabs")) {
            hadminExecutor = new ExportKeytabsCommand(hadmin);
        } else if (cmd.startsWith("enable_configure")
            || cmd.startsWith("enable")) {
            hadminExecutor = new EnableConfigureCommand(hadmin);
        } else if (cmd.startsWith("disable_configure")
            || cmd.startsWith("disable")) {
            hadminExecutor = new DisableConfigureCommand(hadmin);
        } else if (cmd.startsWith("keytab")) {
            hadminExecutor = new KeytabCommand(hadmin);
        } else if (cmd.startsWith("deploy_https")
            || cmd.startsWith("dephttps")) {
            hadminExecutor = new DeployHTTPSCertsCommand(hadmin);
        } else {
            System.out.println(LEGAL_COMMANDS);
            return;
        }
        if (kadminExecutor != null) {
            kadminExecutor.execute(input);
        } else if (hadminExecutor != null) {
            hadminExecutor.execute(items);
        }
    }

    private static File getConfDir(String[] args) {
        String envDir;
        confDir = new File(args[0]);
        if (!confDir.exists()) {
            try {
                Map<String, String> mapEnv = System.getenv();
                envDir = mapEnv.get("KRB5_KDC_DIR");
            } catch (SecurityException e) {
                envDir = null;
            }
            if (envDir != null) {
                confDir = new File(envDir);
            } else {
                confDir = new File("/etc/kerby/"); // for Linux. TODO: fix for Win etc.
            }

            if (!confDir.exists()) {
                throw new RuntimeException("Can not locate KDC backend directory "
                        + confDir.getAbsolutePath());
            }
        }
        LOG.info("Conf dir:" + confDir.getAbsolutePath());
        return confDir;
    }

    public static void main(String[] args) {

        if (args.length < 2) {
            System.err.println(USAGE);
            return;
        }

        LocalKadmin kadmin;
        try {
            kadmin = new LocalKadminImpl(getConfDir(args));
        } catch (KrbException e) {
            System.err.println("Failed to init Kadmin due to " + e.getMessage());
            return;
        }

        LocalHadmin hadmin;
        try {
            hadmin = new LocalHadmin(getConfDir(args));
        } catch (KrbException e) {
            System.err.println("Failed to init Hadmin due to " + e.getMessage());
            return;
        }

        try {
            Krb5Conf krb5Conf = new Krb5Conf(confDir, kadmin.getKdcConfig());
            krb5Conf.initKrb5conf();
        } catch (IOException e) {
            System.err.println("Failed to make krb5.conf." + e.getMessage());
        }

        String kadminPrincipal = kadmin.getKadminPrincipal();


        KOptions kOptions = ToolUtil.parseOptions(args, 1, args.length - 1);
        if (kOptions == null) {
            System.err.println(USAGE);
            return;
        }

        Subject subject = null;
        if (kOptions.contains(KadminOption.CCACHE)) {
            File ccFile = kOptions.getFileOption(KadminOption.CCACHE);
            if (ccFile == null || !ccFile.exists()) {
                printUsage("Need the valid credentials cache file.");
                return;
            }
            try {
                subject = AuthUtil.loginUsingTicketCache(kadminPrincipal, ccFile);
            } catch (LoginException e) {
                System.err.println("Could not login with: " + kadminPrincipal
                    + e.getMessage());
                return;
            }
        } else if (kOptions.contains(KadminOption.K)) {
            File keyTabFile = new File(kOptions.getStringOption(KadminOption.K));
            if (!keyTabFile.exists()) {
                printUsage("Need the valid keytab file.");
                return;
            }
            try {
                subject = AuthUtil.loginUsingKeytab(kadminPrincipal, keyTabFile);
            } catch (LoginException e) {
                System.err.println("Could not login with: " + kadminPrincipal
                    + e.getMessage());
                return;
            }
        } else {
            printUsage("No credentials cache file or keytab file for authentication.");
        }
        if (subject != null) {
            Principal adminPrincipal = new KerberosPrincipal(kadminPrincipal);
            Set<Principal> princSet = subject.getPrincipals();
            if (princSet == null || princSet.isEmpty()) {
                printUsage("The principals in subject is empty.");
                return;
            }
            if (princSet.contains(adminPrincipal)) {
                System.out.println("Login successful for user: " + kadminPrincipal);
            } else {
                printUsage("Login failure for " + kadminPrincipal);
                return;
            }
        } else {
            printUsage("The subject is null, login failure for " + kadminPrincipal);
            return;
        }

        System.out.println("enter \"cmd\" to see legal commands.");

        Completer completer = new StringsCompleter("add_principal",
                "delete_principal", "rename_principal", "change_password", "list_principals",
                "get_principal", "ktadd", "get_hostroles", "export_keytabs", "add_principals",
                "enable_configure", "disable_configure", "keytab", "deploy_https");

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
                execute(kadmin, hadmin, line);
            } catch (HasException e) {
                System.err.println(e.getMessage());
            }
        }
    }
}
