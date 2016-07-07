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
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;

import java.util.List;

public class ListPrincipalCommand extends KadminCommand {
    private static final String USAGE = "Usage: list_principals [expression]\n"
            + "\t'expression' is a shell-style glob expression that can contain the wild-card characters ?, *, and [].";

    public ListPrincipalCommand(LocalKadmin kadmin) {
        super(kadmin);
    }

    @Override
    public void execute(String input) {
        String[] commands = input.split("\\s+");

        if (commands.length <= 2) {
            String expression = commands.length == 2 ? commands[1] : null;
            try {
                List<String> principalNames = getKadmin().getPrincipals(expression);
                if (principalNames.size() == 0) {
                    return;
                }
                System.out.println("Principals are listed:");
                for (String principalName : principalNames) {
                    System.out.println("\t" + principalName);
                }
            } catch (KrbException e) {
                System.err.print("Fail to list principal! " + e.getMessage());
            }
        } else {
            System.err.println(USAGE);
        }
    }
}
