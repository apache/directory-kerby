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
package org.apache.kerby.kerberos.tool.admin.cmd;

import org.apache.kerby.has.client.HasAuthAdminClient;
import org.apache.kerby.kerberos.kerb.KrbException;

import java.util.List;

public class ListPrincipalsRemoteCmd extends AdminRemoteCmd {
    private static final String USAGE = "Usage: list_principals [expression]\n"
            + "\t'expression' is a shell-style glob expression that can contain the wild-card characters ?, *, and []."
            + "\tExample:\n"
            + "\t\tlist_principals [expression]\n";

    public ListPrincipalsRemoteCmd(HasAuthAdminClient authHadmin) {
        super(authHadmin);
    }

    @Override
    public void execute(String[] items) throws KrbException {
        if (items.length > 2) {
            System.err.println(USAGE);
            return;
        }

        HasAuthAdminClient client = getAuthAdminClient();

        List<String> principalLists = null;

        if (items.length == 1) {
            try {
                principalLists = client.getPrincipals();
            } catch (Exception e) {
                System.err.println("Errors occurred when getting the principals. " + e.getMessage());
            }
        } else {
            //have expression
            String exp = items[1];
            principalLists = client.getPrincipals(exp);
        }

        if (principalLists.size() == 0 || principalLists.size() == 1 && principalLists.get(0).isEmpty()) {
            return;
        } else {
            System.out.println("Principals are listed:");
            for (int i = 0; i < principalLists.size(); i++) {
                System.out.println(principalLists.get(i));
            }
        }
    }

}
