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
import org.apache.kerby.kerberos.kerb.admin.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.KadminOption;
import org.apache.kerby.kerberos.tool.kadmin.ToolUtil;

public class AddPrincipalsCommand extends KadminCommand {
    private static final String USAGE = "Usage: add_principals [options]\n"
            + "\toptions are:\n"
            + "[-pwexpire pwexpdate] [-maxlife maxtixlife]\n"
            + "\t\t[-kvno kvno] [-policy policy] [-clearpolicy]\n"
            + "\t\t[-size principal's numbers,must be greater than zero]\n"
            + "\t\t[-e keysaltlist]\n"
            + "\t\t[{+|-}attribute]\n"
            + "\tattributes are:\n"
            + "\t\tallow_postdated allow_forwardable allow_tgs_req allow_renewable\n"
            + "\t\tallow_proxiable allow_dup_skey allow_tix requires_preauth\n"
            + "\t\trequires_hwauth needchange allow_svr password_changing_service\n"
            + "\t\tok_as_delegate ok_to_auth_as_delegate no_auth_data_required\n"
            + "\n"
            + "\twhere,\n"
            + "\t[-x db_princ_args]* - any number of database specific arguments.\n"
            + "\t\t\tLook at each database documentation for supported arguments.\n"
            + "\tExample:\n"
            + "\t\tbatch_anks -expire 23/04/15:01:01:01 -kvno 1 -size 6";


    private KOptions kOptions;

    public AddPrincipalsCommand(LocalKadmin kadmin) {
        super(kadmin);
    }

    @Override
    public void execute(String input) {
        String[] commands = input.split("\\s+");
        if (commands.length < 2) {
            System.err.println(USAGE);
            return;
        }
        kOptions = ToolUtil.parseOptions(commands, 1, commands.length - 1);

        int size;
        if (kOptions.contains(KadminOption.SIZE)) {
            String sizeTemp = kOptions.getStringOption(KadminOption.SIZE);

            String isNum = "^[1-9][0-9]+";
            if (sizeTemp.matches(isNum)) {
                size = Integer.parseInt(sizeTemp);
            } else {
                System.err.println(USAGE);
                return;
            }
        } else {
            System.err.println(USAGE);
            return;
        }

        if (size <= 0) {
            System.err.println(USAGE);
            return;
        }

        int existNumbers = 0;
        try {
            existNumbers = getKadmin().size();
        } catch (KrbException e) {
            e.printStackTrace();
            return;
        }

        addPrincipalForSize(size, existNumbers);
    }

    private void addPrincipalForSize(int size, int existNumbers) {
        int i = 0;
        while (i < size) {
            try {
                int temp = i + existNumbers;
                String principalName = "E" + temp + "@EXAMPLE.COM";
                String password = "12";
                getKadmin().addPrincipal(principalName, password, kOptions);
            } catch (KrbException e) {
                e.printStackTrace();
            }
            i++;
        }

        System.out.println("Principals created");
    }
}
