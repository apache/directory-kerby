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
package org.apache.kerby.kerberos.tool.kadmin.command;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.Kadmin;
import org.apache.kerby.kerberos.kerb.admin.KadminOption;
import org.apache.kerby.kerberos.tool.kadmin.ToolUtil;

import java.io.Console;
import java.util.Arrays;
import java.util.Scanner;

public class ChangePasswordCommand extends KadminCommand {
    private static final String USAGE = "Usage: change_password [-randkey] "
            + "[-keepold] [-e keysaltlist] [-pw password] principal";

    private KOptions kOptions;

    public ChangePasswordCommand(Kadmin kadmin) {
        super(kadmin);
    }

    @Override
    public void execute(String input) {
        String[] commands = input.split("\\s");
        String principal = commands[commands.length - 1];
        String password;

        if (commands.length <= 1) {
            System.err.println(USAGE);
            return;
        }

        if (commands.length == 2) { //only principal is given
            password = getPassword(principal);
            if (password == null) {
                System.out.println("Did not get new password successfully. Please try again");
                return;
            }
            try {
                getKadmin().updatePassword(principal, password);
                System.out.println("Update password success.");
            } catch (KrbException e) {
                System.err.println("Fail to update password. " + e.getCause());
            }
        } else if (commands.length > 2) {
            kOptions = ToolUtil.parseOptions(commands, 1, commands.length - 2);
            if (kOptions == null) {
                System.err.println(USAGE);
                return;
            }
            if (kOptions.contains(KadminOption.PW)) {
                password = kOptions.getStringOption(KadminOption.PW);
                try {
                    getKadmin().updatePassword(principal, password);
                    System.out.println("Update password success.");
                } catch (KrbException e) {
                    System.err.println("Fail to update password. " + e.getMessage());
                }
            } else if (kOptions.contains(KadminOption.RANDKEY)) {
                try {
                    getKadmin().updateKeys(principal);
                } catch (KrbException e) {
                    System.err.println("Fail to update key. " + e.getMessage());
                }
            }
        }
    }

    /**
     * Get password from console
     */
    private String getPassword(String principal) {
        String passwordOnce;
        String passwordTwice;

        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance, "
                    + "maybe you're running this from within an IDE. "
                    + "Use scanner to read password.");
            Scanner scanner = new Scanner(System.in, "UTF-8");
            passwordOnce = getPassword(scanner,
                    "Please enter new password  \"" + principal + "\":");
            passwordTwice = getPassword(scanner,
                    "Please re-enter password  =\"" + principal + "\":");

        } else {
            passwordOnce = getPassword(console,
                    "Please enter new password \"" + principal + "\":");
            passwordTwice = getPassword(console,
                    "Please re-enter password \"" + principal + "\":");
        }

        if (!passwordOnce.equals(passwordTwice)) {
            System.err.println("change_password: Password mismatch while reading password for \"" + principal + "\".");
            return null;
        }
        return passwordOnce;
    }

    private String getPassword(Scanner scanner, String prompt) {
        System.out.println(prompt);
        return scanner.nextLine().trim();
    }

    private String getPassword(Console console, String prompt) {
        console.printf(prompt);
        char[] passwordChars = console.readPassword();
        String password = new String(passwordChars).trim();
        Arrays.fill(passwordChars, ' ');
        return password;
    }
}
