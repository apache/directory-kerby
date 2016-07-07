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
package org.apache.kerby.kerberos.tool.kadmin;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.KadminOption;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.tool.kadmin.command.AddPrincipalCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.ChangePasswordCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.DeletePrincipalCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.GetPrincipalCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.KadminCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.KeytabAddCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.KeytabRemoveCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.ListPrincipalCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.ModifyPrincipalCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.RenamePrincipalCommand;
import org.apache.kerby.kerberos.tool.kadmin.command.AddPrincipalsCommand;
import org.apache.kerby.util.OSUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.LoginException;
import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Scanner;

/**
 * Ref. MIT kadmin command tool usage.
 */
public class KadminTool {
    private static final Logger LOG = LoggerFactory.getLogger(KadminTool.class);
    private static File confDir;

    private static final String PROMPT = KadminTool.class.getSimpleName() + ".local";
    private static final String REQUEST_LIST = "Available " + PROMPT + " requests:\n"
            + "\n"
            + "add_principal, addprinc, ank\n"
            + "                         Add principal\n"
            + "batch_anks, batch\n"
            + "                         Add principals\n"
            + "delete_principal, delprinc\n"
            + "                         Delete principal\n"
            + "modify_principal, modprinc\n"
            + "                         Modify principal\n"
            + "rename_principal, renprinc\n"
            + "                         Rename principal\n"
            + "change_password, cpw     Change password\n"
            + "get_principal, getprinc  Get principal\n"
            + "list_principals, listprincs, get_principals, getprincs\n"
            + "                         List principals\n"
            + "add_policy, addpol       Add policy, not implemented, and will be implemented in next version\n"
            + "modify_policy, modpol    Modify policy, not implemented, and will be implemented in next version\n"
            + "delete_policy, delpol    Delete policy, not implemented, and will be implemented in next version\n"
            + "get_policy, getpol       Get policy, not implemented, and will be implemented in next version\n"
            + "list_policies, listpols, get_policies, getpols, not implemented,"
            + " and will be implemented in next version"
            + "                         List policies\n"
            + "get_privs, getprivs      Get privileges, not implemented, and will be implemented in next version\n"
            + "ktadd, xst               Add entry(s) to a keytab\n"
            + "ktremove, ktrem          Remove entry(s) from a keytab\n"
            + "lock                     Lock database exclusively (use with extreme caution!),"
            + " not implemented, and will be implemented in next version\n"
            + "unlock                   Release exclusive database lock, not implemented,"
            + " and will be implemented in next version\n"
            + "purgekeys                Purge previously retained old keys from a principal, "
            + "not implemented, and will be implemented in next version\n"
            + "get_strings, getstrs     Show string attributes on a principal, not implemented,"
            + " and will be implemented in next version\n"
            + "set_string, setstr       Set a string attribute on a principal, not implemented,"
            + " and will be implemented in next version\n"
            + "del_string, delstr       Delete a string attribute on a principal, not implemented,"
            + " and will be implemented in next version\n"
            + "list_requests, lr, ?     List available requests.\n"
            + "quit, exit, q            Exit program.";

    private static  final String USAGE = (OSUtil.isWindows()
            ? "Usage: bin\\kadmin.cmd" : "Usage: sh bin/kadmin.sh")
            + " <conf-dir> <-c cache_name>|<-k keytab>\n"
            + "\tExample:\n"
            + "\t\t"
            + (OSUtil.isWindows()
            ? "bin\\kadmin.cmd" : "sh bin/kadmin.sh")
            + " conf -k admin.keytab\n";

    private static void printUsage(String error) {
        System.err.println(error + "\n");
        System.err.println(USAGE);
        System.exit(-1);
    }

    private static void execute(LocalKadmin kadmin, String command) {
        //Omit the leading and trailing whitespace.
        command = command.trim();
        if (command.equals("list_requests")
                || command.equals("lr")
                || command.equals("?")) {
            System.out.println(REQUEST_LIST);
            return;
        }

        KadminCommand executor = null;
        if (command.startsWith("add_principal")
                || command.startsWith("addprinc")
                || command.startsWith("ank")) {
            executor = new AddPrincipalCommand(kadmin);
        } else if (command.startsWith("batch_anks")
                || command.startsWith("batch")) {
            executor = new AddPrincipalsCommand(kadmin);
        } else if (command.startsWith("ktadd")
                || command.startsWith("xst")) {
            executor = new KeytabAddCommand(kadmin);
        } else if (command.startsWith("ktremove")
                || command.startsWith("ktrem")) {
            executor = new KeytabRemoveCommand(kadmin);
        } else if (command.startsWith("delete_principal")
                || command.startsWith("delprinc")) {
            executor = new DeletePrincipalCommand(kadmin);
        } else if (command.startsWith("modify_principal")
                || command.startsWith("modprinc")) {
            executor = new ModifyPrincipalCommand(kadmin);
        } else if (command.startsWith("rename_principal")
                || command.startsWith("renprinc")) {
            executor = new RenamePrincipalCommand(kadmin);
        } else if (command.startsWith("change_password")
                || command.startsWith("cpw")) {
            executor = new ChangePasswordCommand(kadmin);
        } else if (command.startsWith("get_principal") || command.startsWith("getprinc")
                || command.startsWith("Get principal")) {
            executor = new GetPrincipalCommand(kadmin);
        } else if (command.startsWith("list_principals")
                || command.startsWith("listprincs") || command.startsWith("get_principals")
                || command.startsWith("getprincs") || command.startsWith("List principals")) {
            executor = new ListPrincipalCommand(kadmin);
        }
        if (executor == null) {
            System.out.println("Unknown request \"" + command + "\". Type \"?\" for a request list.");
            return;
        }
        executor.execute(command);
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

    public static void main(String[] args) throws KrbException {

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

        try {
            Krb5Conf krb5Conf = new Krb5Conf(confDir, kadmin.getKdcConfig());
            krb5Conf.initKrb5conf();
        } catch (IOException e) {
            throw new KrbException("Failed to make krb5.conf", e);
        }

        KOptions kOptions = ToolUtil.parseOptions(args, 1, args.length - 1);
        if (kOptions == null) {
            System.err.println(USAGE);
            return;
        }

        String kadminPrincipal = kadmin.getKadminPrincipal();
        if (kOptions.contains(KadminOption.CCACHE)) {
            File ccFile = kOptions.getFileOption(KadminOption.CCACHE);
            if (ccFile == null || !ccFile.exists()) {
                printUsage("Need the valid credentials cache file.");
                return;
            }
            try {
                AuthUtil.loginUsingTicketCache(kadminPrincipal, ccFile);
            } catch (LoginException e) {
                System.err.println("Could not login with: " + kadminPrincipal
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
                AuthUtil.loginUsingKeytab(kadminPrincipal, keyTabFile);
            } catch (LoginException e) {
                System.err.println("Could not login with: " + kadminPrincipal
                        + e.getMessage());
                return;
            }
        } else {
            printUsage("No credentials cache file or keytab file for authentication.");
        }

        System.out.print(PROMPT + ": ");

        try (Scanner scanner = new Scanner(System.in, "UTF-8")) {
            String input = scanner.nextLine();

            while (!(input.equals("quit") || input.equals("exit")
                    || input.equals("q"))) {
                execute(kadmin, input);
                System.out.print(PROMPT + ": ");
                input = scanner.nextLine();
            }
        }
    }
}
