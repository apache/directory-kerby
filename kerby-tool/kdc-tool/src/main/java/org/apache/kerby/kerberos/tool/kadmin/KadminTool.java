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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.Kadmin;
import org.apache.kerby.kerberos.tool.kadmin.command.*;

import java.io.File;
import java.util.Map;
import java.util.Scanner;

public class KadminTool {
    private static final String PROMPT = KadminTool.class.getSimpleName() + ".local";
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


    private static void execute(Kadmin kadmin, String command) {
        //Omit the leading and trailing whitespace.
        command = command.trim();
        if (command.equals("list_requests") ||
                command.equals("lr") ||
                command.equals("?")) {
            System.out.println(REQUEST_LIST);
            return;
        }

        KadminCommand executor = null;
        if (command.startsWith("add_principal") ||
                command.startsWith("addprinc") ||
                command.startsWith("ank")) {
            executor = new AddPrincipalCommand(kadmin);
        } else if (command.startsWith("ktadd") ||
                command.startsWith("xst")) {
            executor = new KeytabAddCommand(kadmin);
        } else if (command.startsWith("ktremove") ||
                command.startsWith("ktrem")) {
            executor = new KeytabRemoveCommand(kadmin);
        } else if (command.startsWith("delete_principal") ||
                command.startsWith("delprinc")) {
            executor = new DeletePrincipalCommand(kadmin);
        } else if (command.startsWith("modify_principal") ||
                command.startsWith("modprinc")) {
            executor = new ModifyPrincipalCommand(kadmin);
        } else if (command.startsWith("rename_principal") ||
                command.startsWith("renprinc")) {
            executor = new RenamePrincipalCommand(kadmin);
        } else if (command.startsWith("change_password") ||
                command.startsWith("cpw")) {
            executor = new ChangePasswordCommand(kadmin);
        } else if (command.startsWith("get_principal") || command.startsWith("getprinc") ||
                command.startsWith("Get principal")) {
            executor = new GetPrincipalCommand(kadmin);
        } else if (command.startsWith("list_principals") ||
                command.startsWith("listprincs") || command.startsWith("get_principals") ||
                command.startsWith("getprincs") || command.startsWith("List principals")) {
            executor = new ListPrincipalCommand(kadmin);
        }
        if (executor == null) {
            System.out.println("Unknown request \"" + command + "\". Type \"?\" for a request list.");
            return;
        }
        executor.execute(command);
    }

    private static File getConfDir(String[] args) {
        File confDir;
        if (args.length == 0) {
            String envDir;
            try {
                Map<String, String> mapEnv = System.getenv();
                envDir = mapEnv.get("KRB5_KDC_DIR");
            } catch (SecurityException e) {
                envDir = null;
            }
            if(envDir != null) {
                confDir = new File(envDir);
            } else {
                confDir = new File("/etc/kerby/");// for Linux. TODO: fix for Win etc.
            }
        } else {
            confDir = new File(args[0]);
        }

        if (!confDir.exists()) {
            throw new RuntimeException("Can not locate KDC backend directory "
                + confDir.getAbsolutePath());
        }
        return confDir;
    }

    public static void main(String[] args) {
        Kadmin kadmin;
        try {
            kadmin = Kadmin.getInstance(getConfDir(args));
        } catch (KrbException e) {
            System.err.println("Failed to init Kadmin due to " + e.getMessage());
            return;
        }

        System.out.print(PROMPT + ": ");

        try (Scanner scanner = new Scanner(System.in)) {
            String input = scanner.nextLine();

            boolean quit = input.equals("quit") || input.equals("exit") || input.equals("q");
            while (!quit) {
                execute(kadmin, input);
                System.out.print(PROMPT + ": ");
                input = scanner.nextLine();
            }
        }
    }
}
