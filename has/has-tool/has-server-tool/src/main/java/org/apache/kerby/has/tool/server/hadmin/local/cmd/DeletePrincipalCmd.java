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

public class DeletePrincipalCmd extends HadminCmd {

    public static final String USAGE = "Usage: delete_principal <principal-name>\n"
            + "\tExample:\n"
            + "\t\tdelete_principal alice\n";

    private Boolean force = false;

    public DeletePrincipalCmd(LocalHasAdmin hadmin) {
        super(hadmin);
    }

    @Override
    public void execute(String[] items) throws HasException {
        if (items.length < 2) {
            System.err.println(USAGE);
            return;
        }
        String principal = items[items.length - 1];
        String reply;
        Console console = System.console();
        String prompt = "Are you sure to delete the principal? (yes/no, YES/NO, y/n, Y/N) ";
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
            getHadmin().deletePrincipal(principal);
            System.out.println("Success to delete " + principal);
        } else if (reply.equals("no") || reply.equals("NO") || reply.equals("n") || reply.equals("N")) {
            System.out.println("Principal \"" + principal + "\"  not deleted.");
        } else {
            System.err.println("Unknown request, fail to delete the principal.");
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
