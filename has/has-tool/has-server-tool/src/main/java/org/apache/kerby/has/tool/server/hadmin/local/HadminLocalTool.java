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
package org.apache.kerby.has.tool.server.hadmin.local;

import org.apache.kerby.KOptions;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.server.admin.LocalHasAdmin;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.AddPrincipalCmd;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.AddPrincipalsAndDeployKeytabsCmd;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.AddPrincipalsCmd;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.ChangePasswordCmd;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.DeletePrincipalCmd;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.DeployHTTPSCertsCmd;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.DisableConfigureCmd;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.EnableConfigureCmd;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.ExportKeytabsCmd;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.GetHostRolesCmd;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.GetPrincipalCmd;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.HadminCmd;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.KeytabAddCmd;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.ListPrincipalsCmd;
import org.apache.kerby.has.tool.server.hadmin.local.cmd.RenamePrincipalCmd;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.KadminOption;
import org.apache.kerby.kerberos.tool.kadmin.AuthUtil;
import org.apache.kerby.kerberos.tool.kadmin.ToolUtil;
import org.apache.kerby.util.OSUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.security.Principal;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

/**
 * Ref. MIT kadmin cmd tool usage.
 */
public class HadminLocalTool {
    private static final Logger LOG = LoggerFactory.getLogger(HadminLocalTool.class);
    private static File confDir;

    private static final String PROMPT = HadminLocalTool.class.getSimpleName() + ".local";
    private static  final String USAGE = (OSUtil.isWindows()
            ? "Usage: bin\\hadmin-local.cmd" : "Usage: sh bin/kadmin-local.sh")
            + " <conf-dir> <-c cache_name>|<-k keytab>\n"
            + "\tExample:\n"
            + "\t\t"
            + (OSUtil.isWindows()
            ? "bin\\hadmin-local.cmd" : "sh bin/hadmin-local.sh")
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
        + "deploy_keytabs, depkeytabs\n"
        + "                         Deploy keytabs\n"
        + "deploy_https, dephttps\n"
        + "                         Deploy https\n";

    private static void execute(LocalHasAdmin hadmin, String input) throws HasException {
        // Omit the leading and trailing whitespace.
        input = input.trim();
        if (input.startsWith("cmd")) {
            System.out.println(LEGAL_COMMANDS);
            return;
        }

        String[] items = input.split("\\s+");
        String cmd = items[0];
        HadminCmd executor;
        if (cmd.startsWith("add_principal")
            || cmd.startsWith("addprinc")) {
            executor = new AddPrincipalCmd(hadmin);
        } else if (cmd.startsWith("delete_principal")
            || cmd.startsWith("delprinc")) {
            executor = new DeletePrincipalCmd(hadmin);
        } else if (cmd.startsWith("rename_principal")
            || cmd.startsWith("renprinc")) {
            executor = new RenamePrincipalCmd(hadmin);
        } else if (cmd.startsWith("change_password")
                || cmd.startsWith("cpw")) {
            executor = new ChangePasswordCmd(hadmin);
        } else if (cmd.startsWith("list_principals")
            || cmd.startsWith("listprincs")) {
            executor = new ListPrincipalsCmd(hadmin);
        } else if (cmd.startsWith("ktadd")
            || cmd.startsWith("xst")) {
            executor = new KeytabAddCmd(hadmin);
        } else if (cmd.startsWith("get_hostroles")
            || cmd.startsWith("hostroles")) {
            executor = new GetHostRolesCmd(hadmin);
        } else if (cmd.startsWith("create_principals")
            || cmd.startsWith("creprincs")) {
            executor = new AddPrincipalsCmd(hadmin);
        } else if (cmd.startsWith("export_keytabs")
            || cmd.startsWith("expkeytabs")) {
            executor = new ExportKeytabsCmd(hadmin);
        } else if (cmd.startsWith("enable_configure")
            || cmd.startsWith("enable")) {
            executor = new EnableConfigureCmd(hadmin);
        } else if (cmd.startsWith("disable_configure")
            || cmd.startsWith("disable")) {
            executor = new DisableConfigureCmd(hadmin);
        } else if (cmd.startsWith("get_principal")
            || cmd.startsWith("getprinc")) {
            executor = new GetPrincipalCmd(hadmin);
        } else if (cmd.startsWith("deploy_keytabs")
            || cmd.startsWith("depkeytabs")) {
            executor = new AddPrincipalsAndDeployKeytabsCmd(hadmin);
        } else if (cmd.startsWith("deploy_https")
            || cmd.startsWith("dephttps")) {
            executor = new DeployHTTPSCertsCmd(hadmin);
        } else {
            System.out.println(LEGAL_COMMANDS);
            return;
        }
        executor.execute(items);
    }

    private static File getConfDir(String[] args) {
        String envDir;
        confDir = new File(args[0]);
        if (confDir == null || !confDir.exists()) {
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

        LocalHasAdmin hadmin;
        try {
            hadmin = new LocalHasAdmin(getConfDir(args));
        } catch (KrbException e) {
            System.err.println("Failed to init HasAdmin due to " + e.getMessage());
            return;
        }

        KOptions kOptions = ToolUtil.parseOptions(args, 1, args.length - 1);
        if (kOptions == null) {
            System.err.println(USAGE);
            return;
        }

        String hadminPrincipal = hadmin.getHadminPrincipal();
        Subject subject = null;
        if (kOptions.contains(KadminOption.CCACHE)) {
            File ccFile = kOptions.getFileOption(KadminOption.CCACHE);
            if (ccFile == null || !ccFile.exists()) {
                printUsage("Need the valid credentials cache file.");
                return;
            }
            try {
                subject = AuthUtil.loginUsingTicketCache(hadminPrincipal, ccFile);
            } catch (LoginException e) {
                System.err.println("Could not login with: " + hadminPrincipal
                    + e.getMessage());
                return;
            }
        } else if (kOptions.contains(KadminOption.K)) {
            File keyTabFile = new File(kOptions.getStringOption(KadminOption.K));
            if (keyTabFile == null || !keyTabFile.exists()) {
                printUsage("Need the valid keytab file.");
                return;
            }
            try {
                subject = AuthUtil.loginUsingKeytab(hadminPrincipal, keyTabFile);
            } catch (LoginException e) {
                System.err.println("Could not login with: " + hadminPrincipal
                    + e.getMessage());
                return;
            }
        } else {
            printUsage("No credentials cache file or keytab file for authentication.");
        }
        if (subject != null) {
            Principal adminPrincipal = new KerberosPrincipal(hadminPrincipal);
            Set<Principal> princSet = subject.getPrincipals();
            if (princSet == null || princSet.isEmpty()) {
                printUsage("The principals in subject is empty.");
                return;
            }
            if (princSet.contains(adminPrincipal)) {
                System.out.println("Login successful for user: " + hadminPrincipal);
            } else {
                printUsage("Login failure for " + hadminPrincipal);
                return;
            }
        } else {
            printUsage("The subject is null, login failure for " + hadminPrincipal);
            return;
        }
        System.out.println("enter \"cmd\" to see legal commands.");
        System.out.print(PROMPT + ": ");

        try (Scanner scanner = new Scanner(System.in, "UTF-8")) {
            String input = scanner.nextLine();

            while (!(input.equals("quit") || input.equals("exit")
                    || input.equals("q"))) {
                try {
                    execute(hadmin, input);
                } catch (HasException e) {
                    System.err.println(e.getMessage());
                }
                System.out.print(PROMPT + ": ");
                input = scanner.nextLine();
            }
        }
    }
}
