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
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;

public class RemoteChangePasswordCommand extends RemoteCommand {
    private static final String USAGE = "Usage: change_password [-pw newPassword] principal";

    public RemoteChangePasswordCommand(AdminClient adminClient) {
        super(adminClient);
    }

    @Override
    public void execute(String input) throws KrbException {
        String[] items = input.split("\\s+");

        if (items.length < 4) {
            System.err.println(USAGE);
            return;
        }

        String clientPrincipal = items[items.length - 1];

        if (items[1].startsWith("-pw")) {
            String newPassword = items[2];
            adminClient.requestChangePassword(clientPrincipal, newPassword);
            System.out.println("Password updated successfully.");
        } else {
            System.err.println("change_password command error.");
            System.err.println(USAGE);
        }
    }
}