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
package org.apache.kerby.has.tool.server.hadmin.local.cmd;

import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.server.admin.LocalHasAdmin;

import java.io.Console;
import java.util.Scanner;

public class RenamePrincipalCmd extends HadminCmd {
    public static final String USAGE = "Usage: rename_principal <old_principal_name>"
            + " <new_principal_name>\n"
            + "\tExample:\n"
            + "\t\trename_principal alice bob\n";

    public RenamePrincipalCmd(LocalHasAdmin hadmin) {
        super(hadmin);
    }

    @Override
    public void execute(String[] items) throws HasException {
        if (items.length < 3) {
            System.err.println(USAGE);
            return;
        }

        String oldPrincipalName = items[items.length - 2];
        String newPrincipalName = items[items.length - 1];

        String reply;
        Console console = System.console();
        String prompt = "Are you sure to rename the principal? (yes/no, YES/NO, y/n, Y/N) ";
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
            getHadmin().renamePrincipal(oldPrincipalName, newPrincipalName);
            System.out.println("Success to rename principal : \"" + oldPrincipalName
                + "\" to \"" + newPrincipalName + "\".");
        } else if (reply.equals("no") || reply.equals("NO") || reply.equals("n") || reply.equals("N")) {
            System.out.println("Principal \"" + oldPrincipalName + "\"  not renamed.");
        } else {
            System.err.println("Unknown request, fail to rename the principal.");
            System.err.println(USAGE);
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
}
