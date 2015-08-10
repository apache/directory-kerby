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


public class RenamePrincipalCommand extends KadminCommand {
    private static final String USAGE = "Usage: rename_principal [-force] old_principal new_principal\n";

    private KOptions kOptions;
    private String oldPrincipalName;
    private String newPrincipalName;

    public RenamePrincipalCommand(Kadmin kadmin) {
        super(kadmin);
    }

    @Override
    public void execute(String input) {
        String[] commands = input.split("\\s+");
        if (commands.length < 3 || commands.length > 4) {
            System.err.println(USAGE);
            return;
        }

        kOptions = ToolUtil.parseOptions(commands, 1, commands.length - 3);
        if (kOptions == null) {
            System.err.println(USAGE);
            return;
        }
        oldPrincipalName = commands[commands.length - 2];
        newPrincipalName = commands[commands.length - 1];

        if (kOptions.contains(KadminOption.FORCE)) {
            renamePrincipal(getKadmin());
        } else {
            String prompt = "Are you sure want to rename the principal? (yes/no, YES/NO, y/n, Y/N) ";
            String reply = ToolUtil.getReplay(prompt);
            if (reply.equals("yes") || reply.equals("YES") || reply.equals("y") || reply.equals("Y")) {
                renamePrincipal(getKadmin());
            } else if (reply.equals("no") || reply.equals("NO") || reply.equals("n") || reply.equals("N")) {
                System.out.println("Principal \"" + oldPrincipalName + "\"  not renamed.");
            } else {
                System.err.println("Unknown response, fail to rename the principal.");
            }
        }
    }

    public void renamePrincipal(Kadmin kadmin) {
        try {
            kadmin.renamePrincipal(oldPrincipalName, newPrincipalName);
            System.out.println("Principal \"" + oldPrincipalName + "\" renamed to \""
                    + newPrincipalName + "\".");
        } catch (KrbException e) {
            System.err.println("Principal rename failed! Exception happened. " + e.getMessage());
        }
    }
}
