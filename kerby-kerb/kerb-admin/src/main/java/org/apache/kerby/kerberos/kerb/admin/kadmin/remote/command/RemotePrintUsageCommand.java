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
package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command;

import org.apache.kerby.kerberos.kerb.KrbException;

public class RemotePrintUsageCommand extends RemoteCommand {

    private static final String LISTPRINCSUSAGE = "Usage: list_principals [expression]\n"
            + "\t'expression' is a shell-style glob expression that can contain "
            + "the wild-card characters ?, *, and [].\n"
            + "\tExample:\n"
            + "\t\tlist_principals [expression]\n";

    public RemotePrintUsageCommand() {
        super(null);
    }

    @Override
    public void execute(String input) throws KrbException {
        if (input.startsWith("listprincs")) {
            System.out.println(LISTPRINCSUSAGE);
        }
    }
}
