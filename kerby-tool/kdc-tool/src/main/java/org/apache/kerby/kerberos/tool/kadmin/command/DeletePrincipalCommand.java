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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.Kadmin;

import java.io.Console;
import java.util.Scanner;

public class DeletePrincipalCommand extends KadminCommand {

    private static final String USAGE = "Usage: delete_principal [options] principal\n"
            + "This command prompts for deletion, unless the -force option is given.\n"
            + "\toptions are:\n"
            + "\t\t[-force]" + " no prompts for deletion.";

    private Boolean force = false;

    public DeletePrincipalCommand(Kadmin kadmin) {
        super(kadmin);
    }

    @Override
    public void execute(String input) {
        String[] commands = input.split(" ");
        if (commands.length < 2) {
            System.err.println(USAGE);
            return;
        }

        parseOptions(commands);
        String principal = commands[commands.length - 1];

        if (force) {
            deletePrincipal(getKadmin(), principal);
        } else {
            String reply;
            Console console = System.console();
            String prompt = "Are you sure want to delete the principal? (yes/no, YES/NO, y/n, Y/N) ";
            if (console == null) {
                System.out.println("Couldn't get Console instance, "
                        + "maybe you're running this from within an IDE. "
                        + "Use scanner to read password.");
                Scanner scanner = new Scanner(System.in, "UTF-8");
                reply = getReply(scanner, prompt);
            } else {
                reply = getReply(console, prompt);
            }
            if (reply.equals("yes") || reply.equals("YES") || reply.equals("y") || reply.equals("Y")) {
                deletePrincipal(getKadmin(), principal);
            } else if (reply.equals("no") || reply.equals("NO") || reply.equals("n") || reply.equals("N")) {
                System.out.println("Pincipal \"" + principal + "\"  not deleted.");
            } else {
                System.err.println("Unknow request, fail to delete the principal.");
            }
        }
    }

    private void deletePrincipal(Kadmin kadmin, String principal) {
        try {
            kadmin.deletePrincipal(principal);
            System.out.println("Principal \"" + principal + "\" deleted.");
        } catch (KrbException e) {
            System.err.println("Fail to delete principal \"" + principal + "\" ." + e.getMessage());
        }
    }

    private String getReply(Scanner scanner, String prompt) {
        System.out.println(prompt);
        return scanner.nextLine().trim();
    }

    private String getReply(Console console, String prompt) {
        console.printf(prompt);
        String line = console.readLine();
        return line;
    }

    private void parseOptions(String[] commands) {
        if (commands[1].equals("-force")) {
            force = true;
        }
    }
}
