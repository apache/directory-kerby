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

import org.apache.kerby.KOptionType;
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.Kadmin;
import org.apache.kerby.kerberos.kerb.admin.KadminOption;
import org.apache.kerby.kerberos.tool.kadmin.ToolUtil;

public class ModifyPrincipalCommand extends KadminCommand {
    private static final String USAGE = "Usage: modify_principal [options] principal\n"
            + "\toptions are:\n"
            + "\t\t[-expire dd/MM/yy:HH:mm:ss]\n"
            + "\t\t[-disabled true/false]\n"
            + "\t\t[-locked true/false]\n"
            + "\tExample:\n"
            + "\t\tmodify_principal -expire 23/04/15:01:01:01 -disabled false "
            + "-locked true test@EXAMPLE.COM";

    private KOptions kOptions;
    private String principal;

    public ModifyPrincipalCommand(Kadmin kadmin) {
        super(kadmin);
        this.kOptions = new KOptions();
    }

    @Override
    public void execute(String input) {
        String[] commands = input.split(" ");
        if (commands.length < 2) {
            ToolUtil.printUsage("missing operand!", USAGE);
            return;
        }
        parseOptions(commands);

        try {
            getKadmin().modifyPrincipal(principal, kOptions);
            System.out.println("Principal \"" + principal + "\" modified.");
        } catch (KrbException e) {
            System.err.println("Principal \"" + principal + "\" fail to modify. " + e.getMessage());
        }
    }

    private void parseOptions(String[] commands) {
        KadminOption kOption;
        String opt, error, param;
        int i = 1;
        while (i < commands.length) {
            error = null;
            opt = commands[i++];
            if (opt.startsWith("-")) {
                kOption = KadminOption.fromName(opt);
                if (kOption == KadminOption.NONE) {
                    error = "Invalid option:" + opt;
                    System.err.println(error);
                    break;
                }
            } else {
                principal = opt;
                kOption = KadminOption.NONE;
            }

            if (kOption.getType() != KOptionType.NOV) { // require a parameter
                param = null;
                if (i < commands.length) {
                    param = commands[i++];
                }
                if (param != null) {
                    KOptions.parseSetValue(kOption, param);
                } else {
                    error = "Option " + opt + " require a parameter";
                }
            }
            if (error != null) {
                ToolUtil.printUsage(error, USAGE);
            }
            kOptions.add(kOption);
        }
        if (principal == null) {
            ToolUtil.printUsage("missing principal name!", USAGE);
        }
    }
}
