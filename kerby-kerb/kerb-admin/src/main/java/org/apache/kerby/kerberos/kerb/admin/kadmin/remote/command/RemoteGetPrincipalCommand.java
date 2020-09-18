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
import org.apache.kerby.kerberos.kerb.request.KrbIdentity;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;

public class RemoteGetPrincipalCommand extends RemoteCommand {
    private static final String USAGE = "Usage: getprinc principalName\n"
            + "\tExample:\n"
            + "\t\tgetprinc hello@TEST.COM\n";

    public RemoteGetPrincipalCommand(AdminClient adminClient) {
        super(adminClient);
    }

    @Override
    public void execute(String input) throws KrbException {
        String[] items = input.split("\\s+");
        if (items.length != 2) {
            System.err.println(USAGE);
            return;
        }

        String clientPrincipalName = items[items.length - 1];
        KrbIdentity identity = null;
        try {
            identity = adminClient.requestGetPrincipal(clientPrincipalName);
        } catch (KrbException e) {
            System.err.println("Failed to get principal: " + clientPrincipalName + ". " + e.toString());
        }
        if (identity == null) {
            return;
        } else {
            System.out.println("Principal is listed:");
            System.out.println(
                    "Principal: " + identity.getPrincipalName() + "\n"
                            + "Expiration date: " + identity.getExpireTime() + "\n"
                            + "Created time: " + identity.getCreatedTime() + "\n"
                            + "KDC flags: " + identity.getKdcFlags() + "\n"
                            + "Key version: " + identity.getKeyVersion() + "\n"
                            + "Number of keys: " + identity.getKeys().size()
            );

            for (EncryptionType keyType: identity.getKeys().keySet()) {
                System.out.println("key: " + keyType);
            }
        }
    }
}