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

import java.util.List;

public class ListPrincipalsCmd extends HadminCmd {
    private static final String USAGE = "Usage: list_principals [expression]\n"
            + "\t'expression' is a shell-style glob expression that can contain the wild-card characters ?, *, and []."
            + "\tExample:\n"
            + "\t\tlist_principals [expression]\n";

    public ListPrincipalsCmd(LocalHasAdmin hadmin) {
        super(hadmin);
    }

    @Override
    public void execute(String[] items) throws HasException {
        if (items.length > 2) {
            System.err.println(USAGE);
            return;
        }

        List<String> principalLists = null;

        if (items.length == 1) {
            principalLists = getHadmin().getPrincipals();
        } else {
            //have expression
            String exp = items[1];
            principalLists = getHadmin().getPrincipals(exp);
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
