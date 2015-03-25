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

import org.apache.kerby.config.Conf;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.tool.kadmin.executor.AddPrincipalExecutor;
import org.apache.kerby.kerberos.tool.kadmin.executor.KadminCommandExecutor;
import org.apache.kerby.kerberos.tool.kadmin.executor.KeytabAddExecutor;

import java.io.File;
import java.io.IOException;
import java.util.Scanner;

public class Kadmin {
    private static final String PROMPT = Kadmin.class.getSimpleName() + ".local";
    private static final String REQUEST_LIST = "Available " + PROMPT + " requests:\n" +
            "\n" +
            "add_principal, addprinc, ank\n" +
            "                         Add principal\n" +
            "delete_principal, delprinc\n" +
            "                         Delete principal\n" +
            "modify_principal, modprinc\n" +
            "                         Modify principal\n" +
            "rename_principal, renprinc\n" +
            "                         Rename principal\n" +
            "change_password, cpw     Change password\n" +
            "get_principal, getprinc  Get principal\n" +
            "list_principals, listprincs, get_principals, getprincs\n" +
            "                         List principals\n" +
            "add_policy, addpol       Add policy\n" +
            "modify_policy, modpol    Modify policy\n" +
            "delete_policy, delpol    Delete policy\n" +
            "get_policy, getpol       Get policy\n" +
            "list_policies, listpols, get_policies, getpols\n" +
            "                         List policies\n" +
            "get_privs, getprivs      Get privileges\n" +
            "ktadd, xst               Add entry(s) to a keytab\n" +
            "ktremove, ktrem          Remove entry(s) from a keytab\n" +
            "lock                     Lock database exclusively (use with extreme caution!)\n" +
            "unlock                   Release exclusive database lock\n" +
            "purgekeys                Purge previously retained old keys from a principal\n" +
            "get_strings, getstrs     Show string attributes on a principal\n" +
            "set_string, setstr       Set a string attribute on a principal\n" +
            "del_string, delstr       Delete a string attribute on a principal\n" +
            "list_requests, lr, ?     List available requests.\n" +
            "quit, exit, q            Exit program.";

    private static KdcConfig kdcConfig;
    private static Conf backendConfig;

    private static void execute(String command) {
        if (command.equals("list_requests") ||
                command.equals("lr") ||
                command.equals("?")) {
            System.out.println(REQUEST_LIST);
            return;
        }

        KadminCommandExecutor executor = null;
        if (command.startsWith("add_principal") ||
                command.startsWith("addprinc") ||
                command.startsWith("ank")) {
            executor = new AddPrincipalExecutor(kdcConfig, backendConfig);
        } else if (command.startsWith("ktadd") ||
                command.startsWith("xst")) {
            executor = new KeytabAddExecutor(backendConfig);
        }

        if (executor == null) {
            System.out.println("Unknown request \"" + command + "\". Type \"?\" for a request list.");
            return;
        }
        executor.execute(command);
    }

    private static void initConfig(String[] args) {
        File confDir;
        if (args.length == 0) {
            confDir = new File("/etc/kerby/");// for Linux. TODO: fix for Win etc.
        } else {
            confDir = new File(args[0]);
        }

        if (confDir.exists()) {
            File kdcConfFile = new File(confDir, "kdc.conf");
            if (kdcConfFile.exists()) {
                kdcConfig = new KdcConfig();
                try {
                    kdcConfig.addIniConfig(kdcConfFile);
                } catch (IOException e) {
                    System.err.println("Can not load the kdc configuration file " + kdcConfFile.getAbsolutePath());
                    e.printStackTrace();
                }
            }

            File backendConfigFile = new File(confDir, "backend.conf");
            if (backendConfigFile.exists()) {
                backendConfig = new Conf();
                try {
                    backendConfig.addIniConfig(backendConfigFile);
                } catch (IOException e) {
                    System.err.println("Can not load the backend configuration file " + backendConfigFile.getAbsolutePath());
                    e.printStackTrace();
                }
            }
        } else {
            throw new RuntimeException("Can not find configuration directory");
        }
    }

    public static void main(String[] args) {
        initConfig(args);
        System.out.print(PROMPT + ": ");
        Scanner scanner = new Scanner(System.in);
        String input = scanner.nextLine();

        while (!(input.equals("quit") ||
                input.equals("exit") ||
                input.equals("q"))) {
            execute(input);
            System.out.print(PROMPT + ": ");
            input = scanner.nextLine();
        }
    }
}
