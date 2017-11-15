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
package org.apache.hadoop.has.tool.server.hadmin.local.cmd;

import org.apache.hadoop.has.common.HasException;
import org.apache.hadoop.has.server.admin.LocalHasAdmin;

public class AddPrincipalCmd extends HadminCmd {

    public static final String USAGE = "Usage: add_principal [options] <principal-name>\n"
            + "\toptions are:\n"
            + "\t\t[-randkey]\n"
            + "\t\t[-pw password]"
            + "\tExample:\n"
            + "\t\tadd_principal -pw mypassword alice\n";

    public AddPrincipalCmd(LocalHasAdmin hadmin) {
        super(hadmin);
    }

    @Override
    public void execute(String[] items) throws HasException {

        if (items.length < 2) {
            System.err.println(USAGE);
            return;
        }

        String clientPrincipal = items[items.length - 1];
        if (!items[1].startsWith("-")) {
            getHadmin().addPrincipal(clientPrincipal);
        } else if (items[1].startsWith("-randkey")) {
            getHadmin().addPrincipal(clientPrincipal);
        } else if (items[1].startsWith("-pw")) {
            String password = items[2];
            getHadmin().addPrincipal(clientPrincipal, password);
        } else {
            System.err.println("add_principal cmd format error.");
            System.err.println(USAGE);
            return;
        }
        System.out.println("Success to add principal :" + clientPrincipal);
    }
}
